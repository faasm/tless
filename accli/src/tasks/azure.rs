use crate::env::Env;
use anyhow::Result;
use base64::Engine;
use clap::Subcommand;
use log::{debug, error, info};
use reqwest::Client;
use serde_json::Value;
use shellexpand;
use std::{
    collections::HashMap,
    fs,
    process::{Command, ExitStatus},
    time::Duration,
};

const AZURE_RESOURCE_GROUP: &str = "faasm";
pub const AZURE_USERNAME: &str = "accless";
const AZURE_LOCATION: &str = "eastus";

const AZURE_SSH_PRIV_KEY: &str = "~/.ssh/id_rsa";
const AZURE_SSH_PUB_KEY: &str = "~/.ssh/id_rsa.pub";

const AZURE_SGX_VM_IMAGE: &str = "Canonical:ubuntu-24_04-lts:server:latest";
const AZURE_SNP_CC_VM_SIZE: &str = "/CommunityGalleries/cocopreview-91c44057-c3ab-4652-bf00-9242d5a90170/Images/ubu2204-snp-host-upm/Versions/latest";

//  Specifies order in which to delete resource types
const RESOURCE_TYPE_PRECEDENCE: [&str; 4] = [
    "Microsoft.Network/networkInterfaces",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/virtualNetworks",
    "Microsoft.Network/publicIpAddresses",
];

#[derive(Debug, Subcommand)]
pub enum AzureUtilsCommand {
    /// Check if we are inside an Azure VM or not.
    InAzureVm {},
}

#[derive(Debug)]
pub struct Azure {}

impl Azure {
    // -------------------------------------------------------------------------
    // Misc Helpers
    // -------------------------------------------------------------------------

    #[allow(dead_code)]
    fn create_self_signed_cert(key_out_path: &str, cert_out_path: &str) -> Result<()> {
        let openssl_cmd = format!(
            "openssl req -newkey rsa:2048 -nodes -keyout {key_out_path} \
            -subj \"/O=TLess/OU=TLess/CN=TLess-mhsm-cert\" \
            -x509 -days 365 -out {cert_out_path}"
        );
        Self::run_cmd_check_status(
            &openssl_cmd,
            "error generating self-signed openssl certificate",
        )?;

        Ok(())
    }

    /// Helper function to check if we are inside an azure cVM or not.
    pub async fn is_azure_vm() -> bool {
        // The specific URL for Azure Instance Metadata
        let url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";

        let client = Client::builder()
            .timeout(Duration::from_millis(250))
            .build()
            .unwrap_or_else(|_| Client::new());

        // Must set the metadata header.
        let response = client.get(url).header("Metadata", "true").send().await;

        match response {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    pub fn accless_vm_code_dir() -> String {
        format!("/home/{AZURE_USERNAME}/git/faasm/accless")
    }

    // -------------------------------------------------------------------------
    // Command Helpers
    // -------------------------------------------------------------------------

    fn run_cmd(cmd: &str) -> Result<ExitStatus> {
        Ok(Command::new("sh").arg("-c").arg(cmd).status()?)
    }

    fn run_cmd_check_status(cmd: &str, error_msg: &str) -> Result<()> {
        let status = Self::run_cmd(cmd)?;

        if !status.success() {
            let reason = format!("error running command (error={error_msg})");
            error!("run_cmd_check_status(): {reason}");
            anyhow::bail!(reason);
        } else {
            Ok(())
        }
    }

    fn run_cmd_get_output(cmd: &str) -> Result<String> {
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;

        let stdout = String::from_utf8(output.stdout)?;
        Ok(stdout.trim().to_string())
    }

    // -------------------------------------------------------------------------
    // Azure Helpers
    // -------------------------------------------------------------------------

    /// Activate a managed HSM by providing three certificates for the security
    /// domain
    #[allow(dead_code)]
    fn activate_managed_hsm(mhsm_name: &str) -> Result<()> {
        let key_dir = Env::proj_root().join("config").join("azure").join("keys");
        fs::create_dir_all(&key_dir).expect("invrs: failed to create key directory");

        Self::create_self_signed_cert(
            key_dir.join("cert0.key").to_str().unwrap(),
            key_dir.join("cert0.cert").to_str().unwrap(),
        )?;
        Self::create_self_signed_cert(
            key_dir.join("cert1.key").to_str().unwrap(),
            key_dir.join("cert1.cert").to_str().unwrap(),
        )?;
        Self::create_self_signed_cert(
            key_dir.join("cert2.key").to_str().unwrap(),
            key_dir.join("cert2.cert").to_str().unwrap(),
        )?;

        let key_dir_str = key_dir.to_str().unwrap();
        let az_cmd = format!(
            "az keyvault security-domain download --hsm-name {mhsm_name} \
            --sd-wrapping-keys {key_dir_str}/cert0.cert {key_dir_str}/cert1.cert \
            {key_dir_str}/cert2.cert --sd-quorum 2 \
            --security-domain-file {key_dir_str}/{mhsm_name}-sd.json"
        );
        Self::run_cmd_check_status(&az_cmd, "error activating managed HSM")
    }

    fn delete_resource(name: &str, resource_type: &str) {
        info!("deleting resource: {name} (type: {resource_type})");

        let cmd = format!(
            "az resource delete --resource-group {AZURE_RESOURCE_GROUP} \
            --name {name} --resource-type {resource_type}"
        );
        // Some delete operations may fail sometimes, we still want to make
        // progress
        if Self::run_cmd(&cmd).is_err() {
            error!(
                "delete_resource(): failed to delete resource (name={name}, type={resource_type})"
            );
        }
    }

    fn delete_resources(resources: Vec<Value>) {
        let mut deleted_resources: Vec<String> = vec![];

        for resource_type in RESOURCE_TYPE_PRECEDENCE {
            let resources_to_delete: Vec<Value> = resources
                .clone()
                .into_iter()
                .filter(|v| {
                    v["type"]
                        .as_str()
                        .map(|r_type| r_type == resource_type)
                        .unwrap_or(false)
                })
                .collect();

            for resource in resources_to_delete {
                Self::delete_resource(
                    resource["name"].as_str().unwrap(),
                    resource["type"].as_str().unwrap(),
                );
                deleted_resources.push(resource.clone()["id"].to_string());
            }
        }

        let remaining_resources: Vec<Value> = resources
            .clone()
            .into_iter()
            .filter(|v| {
                v["id"]
                    .as_str()
                    .map(|r_id| !deleted_resources.contains(&r_id.to_string()))
                    .unwrap_or(false)
            })
            .collect();

        for resource in remaining_resources {
            Self::delete_resource(
                resource["name"].as_str().unwrap(),
                resource["type"].as_str().unwrap(),
            );
        }
    }

    pub fn get_aa_attest_uri(aa_name: &str) -> Result<String> {
        let az_cmd = format!(
            "az attestation show --name {aa_name} --resource-group {AZURE_RESOURCE_GROUP} \
            --query attestUri --output tsv"
        );
        Self::run_cmd_get_output(&az_cmd)
    }

    pub fn get_key_uri(kv_name: &str, key_name: &str) -> Result<String> {
        let az_cmd = format!(
            "az keyvault show --vault-name {kv_name} --name {key_name} \
            --query \"key.kid\" --output tsv"
        );
        Self::run_cmd_get_output(&az_cmd)
    }

    fn get_managed_identity_oid(vm_name: &str) -> Result<String> {
        let subscription_id = Self::get_subscription_id()?;
        let resource_id = format!(
            "/subscriptions/{subscription_id}/resourceGroups\
            /{AZURE_RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines\
            /{vm_name}"
        );

        let az_cmd = format!(
            "az resource show --ids {resource_id} \
            --query \"identity.principalId\" -o tsv"
        );
        Self::run_cmd_get_output(&az_cmd)
    }

    fn get_subscription_id() -> Result<String> {
        let az_cmd = "az account show --query id --output tsv";
        Self::run_cmd_get_output(az_cmd)
    }

    pub fn get_vm_ip(vm_name: &str) -> Result<String> {
        let az_cmd = format!("az vm list-ip-addresses -n {vm_name} -g {AZURE_RESOURCE_GROUP}");
        let stdout = Self::run_cmd_get_output(&az_cmd)?;
        let json: Vec<Value> = serde_json::from_str(&stdout)?;

        if json.is_empty() {
            let reason = format!("no VMs found with requested name (name={vm_name})");
            error!("get_vm_ip(): {reason}");
            anyhow::bail!(reason);
        }

        match json[0]["virtualMachine"]["network"]["publicIpAddresses"][0]["ipAddress"].as_str() {
            Some(ip) => Ok(ip.to_string()),
            None => {
                let reason = format!("error getting VM ip (name={vm_name})");
                error!("get_vm_ip(): {reason}");
                anyhow::bail!(reason);
            }
        }
    }

    /// List all resources of type `resource` beginning with prefix `prefix
    fn list_all_resources(resource: &str, prefix: Option<&str>) -> Result<Vec<Value>> {
        let az_cmd = format!("az {resource} list --resource-group {AZURE_RESOURCE_GROUP}");
        let stdout = Self::run_cmd_get_output(&az_cmd)?;
        let json: Vec<Value> =
            serde_json::from_str(&stdout).expect("invrs: error: invalid JSON from az command");

        // Filter by name prefix
        if let Some(prefix_str) = prefix {
            Ok(json
                .into_iter()
                .filter(|v| {
                    v["name"]
                        .as_str()
                        .map(|name| name.starts_with(prefix_str))
                        .unwrap_or(false)
                })
                .collect())
        } else {
            Ok(json)
        }
    }

    /// Open a list of ports in a VM. Note that, given that we do not set
    /// priorities in the port rules, trying to run the same method twice
    /// on the same VM will fail. Hence why we support passing a list of ports
    /// so that the operation is only done once.
    pub fn open_vm_ports(vm_name: &str, ports: &[usize]) -> Result<()> {
        info!("open_vm_ports(): opening VM ports (name={vm_name}, ports={ports:?})");
        let port_str = ports
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let az_cmd = format!(
            "az vm open-port --resource-group {AZURE_RESOURCE_GROUP} \
            --name {vm_name} --port {port_str}"
        );
        Self::run_cmd_get_output(&az_cmd)?;
        Ok(())
    }

    /// Perform an arbitrary operation `op` on a VM with name `name`. We can
    /// pass additional arguments via extra_args: `["--yes", "--no"]`
    fn vm_op(op: &str, name: &str, extra_args: &[&str]) -> Result<()> {
        info!("vm_op(): performing op on vm (name={name}, op={op})");

        let extra = extra_args.join(" ");
        let cmd = format!(
            "az vm {} --resource-group {} --name {} {}",
            op, AZURE_RESOURCE_GROUP, name, extra
        );
        Self::run_cmd_check_status(&cmd, "failed to execute vm_op")
    }

    // -------------------------------------------------------------------------
    // Create/Delete Azure Resources
    // -------------------------------------------------------------------------

    // ------------------------------ SGX VMs ---------------------------------

    // SGXv2 VMs in Azure are in the DCdsv3 family:
    // https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcdsv3-series
    pub fn create_sgx_vm(vm_name: &str, vm_sku: &str) -> Result<()> {
        info!("creating sgx vm: {vm_name} (sku: {vm_sku})");
        let az_cmd = format!(
            "az vm create --resource-group {AZURE_RESOURCE_GROUP} \
            --name {vm_name} --admin-username {AZURE_USERNAME} --location \
            {AZURE_LOCATION} --ssh-key-value {AZURE_SSH_PUB_KEY} \
            --image {AZURE_SGX_VM_IMAGE} --size {vm_sku} --os-disk-size-gb 128 \
            --public-ip-sku Standard --os-disk-delete-option delete \
            --data-disk-delete-option delete --nic-delete-option delete"
        );
        Self::run_cmd(&az_cmd)?;

        Ok(())
    }

    pub fn delete_sgx_vm(vm_name: &str) -> Result<()> {
        // First delete VM
        if Self::vm_op("delete", vm_name, &["--yes"]).is_err() {
            error!("delete_sgx_vm(): error deleting SGX VM");
        }

        // Then delete all attached resources
        let all_resources = Self::list_all_resources("resource", Some(vm_name))?;
        Self::delete_resources(all_resources);

        Ok(())
    }

    // ------------------------------ SNP cVMs ---------------------------------

    // Readily-available cVMs (i.e. SNP guests) in Azure are in the DCasv5 series:
    // https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcasv5-series
    pub fn create_snp_guest(vm_name: &str, vm_sku: &str) -> Result<()> {
        info!("create_snp_guest(): creating SNP cVM (name={vm_name},sku={vm_sku})");

        let parameter_file = Env::proj_root()
            .join("config")
            .join("azure")
            .join("snp_guest_parameters.json");
        let template_file = Env::proj_root()
            .join("config")
            .join("azure")
            .join("snp_guest_template.json");
        let cloud_init_file = Env::proj_root()
            .join("config")
            .join("azure")
            .join("snp_guest_cloud-init.txt");

        let cinit_content = fs::read(cloud_init_file).expect("error: reading cloud-init file");
        let custom_data = base64::engine::general_purpose::STANDARD.encode(cinit_content);

        let pub_key = fs::read_to_string(shellexpand::tilde(AZURE_SSH_PUB_KEY).into_owned())
            .expect("invrs: error loading ssh pub key");
        let az_cmd = format!(
            "az deployment group create --resource-group {AZURE_RESOURCE_GROUP} \
            --name {vm_name} --template-file {} --parameters {} \
            --parameters vmName={vm_name} --parameters vmSize={vm_sku} \
            --parameters adminPasswordOrKey='{pub_key}' --parameters \
            adminUsername={AZURE_USERNAME} --parameters customData='{custom_data}'",
            template_file.display(),
            parameter_file.display()
        );

        // Get output but ignore it to have a clean log.
        Self::run_cmd_get_output(&az_cmd)?;

        Ok(())
    }

    pub fn delete_snp_guest(vm_name: &str) -> Result<()> {
        info!("delete_snp_guest(): deleting snp cVM (name={vm_name})");

        // First delete VM
        if Self::vm_op("delete", vm_name, &["--yes"]).is_err() {
            error!("delete_snp_guest(): error deleting snp cVM");
        }

        // Then delete all attached resources
        let all_resources = Self::list_all_resources("resource", Some(vm_name))?;
        Self::delete_resources(all_resources);

        let az_cmd = format!("az deployment group delete -g {AZURE_RESOURCE_GROUP} -n {vm_name}",);
        Self::run_cmd(&az_cmd)?;

        Ok(())
    }

    // ------------------------------ SNP cc-VMs -------------------------------

    // SNP child-chapable VMs are regular VMs that support creating SNP
    // protected child VMs. Note that the parent VM is _not_ running in an SNP
    // guest, only the child
    // https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcasccv5-series
    pub fn create_snp_cc_vm(vm_name: &str, vm_sku: &str) -> Result<()> {
        info!("creating snp cc-vm: {vm_name} (sku: {vm_sku})");
        let az_cmd = format!(
            "az vm create --resource-group {AZURE_RESOURCE_GROUP} \
            --name {vm_name} --admin-username {AZURE_USERNAME} --location \
            {AZURE_LOCATION} --ssh-key-value {AZURE_SSH_PUB_KEY} \
            --image {AZURE_SNP_CC_VM_SIZE} --size {vm_sku} --os-disk-size-gb 128 \
            --accelerated-networking true --accept-term"
        );
        Self::run_cmd(&az_cmd)?;

        Ok(())
    }

    pub fn delete_snp_cc_vm(vm_name: &str) -> Result<()> {
        info!("delete_snp_cc_vm(): deleting snp cc VM (name={vm_name})");
        // First delete VM
        if Self::vm_op("delete", vm_name, &["--yes"]).is_err() {
            error!("delete_snp_cc_vm(): error deleting snp cc VM");
        }

        // Then delete all attached resources
        let all_resources = Self::list_all_resources("resource", Some(vm_name))?;
        Self::delete_resources(all_resources);

        Ok(())
    }

    // ---------------------------- Managed HSM --------------------------------

    /// This method creates a managed HSM (mHSM) on Azure, and activates it.
    /// It also gives `vm_name` the rights to perform key-release operations
    /// on the mHSM. Lastly, it populates the mHSM with a key (`key_name`)
    /// whose release is protected by an access policy that depends on an
    /// attestation token granted by an Azure Attestation instance.
    ///
    /// This scenario is a standard secure key release (SKR) scenario,
    /// as described here:
    /// https://learn.microsoft.com/en-us/azure/confidential-computing/concept-skr-attestation
    /// https://github.com/Azure/confidential-computing-cvm-guest-attestation/tree/main/cvm-securekey-release-app
    ///
    /// WARNING: creating a managed HSM can take between 15 to 30 minutes. To
    /// avoid this cost, for the time being we use an AKV with premium SKU.
    pub fn create_mhsm(mhsm_name: &str, vm_name: &str, key_name: &str) -> Result<()> {
        info!("creating managed hsm: {mhsm_name} (paired with vm: {vm_name})");

        // Create managed HSM
        // FIXME: allocating a mHSM can take between 15 to 30'. To avoid this,
        // and for the time being, we run the tests with an AKV with the
        // `premium` SKU.
        // let az_cmd = "az ad signed-in-user show --query id -o tsv";
        // let oid = Self::run_cmd_get_output(az_cmd, "error showing user id");
        // let az_cmd = format!(
        // "az keyvault create --hsm-name {mhsm_name} \
        // --resource-group {AZURE_RESOURCE_GROUP} \
        // --location {AZURE_LOCATION} --administrators {} \
        // --enable-rbac-authorization false \
        // --retention-days 7", oid.trim());
        let az_cmd = format!(
            "az keyvault create --name {mhsm_name} \
            --resource-group {AZURE_RESOURCE_GROUP} --sku premium \
            --enable-rbac-authorization false"
        );
        Self::run_cmd_check_status(&az_cmd, "error creating managed-hsm")?;

        // FIXME: see above
        // Activate managed HSM
        // Self::activate_managed_hsm(&mhsm_name);

        // Give our cVM key-release access in this managed HSM
        let az_cmd = format!(
            "az keyvault set-policy --name {mhsm_name} \
            --object-id {} --key-permissions release",
            Self::get_managed_identity_oid(vm_name)?
        );
        Self::run_cmd_check_status(&az_cmd, "error granting cVM access to mHSM")?;

        // Create an exportable key with an attached key-release policy. Given
        // that we use a managed HSM, we must select a key type with the -HSM
        // extension:
        // https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys
        let az_cmd = format!(
            "az keyvault key create --exportable true --vault-name {mhsm_name} \
            --kty RSA-HSM --name {key_name} --policy {}",
            Env::proj_root()
                .join("config")
                .join("azure")
                .join("mhsm_skr_policy.json")
                .display()
        );
        Self::run_cmd_check_status(&az_cmd, "error creating key with release policy")?;

        Ok(())
    }

    pub fn delete_mhsm(mhsm_name: &str) -> Result<()> {
        // FIXME: see above
        // let az_cmd = format!(
        // "az keyvault delete --hsm-name {mhsm_name} \
        // --resource-group {AZURE_RESOURCE_GROUP}");
        let az_cmd = format!(
            "az keyvault delete --name {mhsm_name} \
            --resource-group {AZURE_RESOURCE_GROUP}"
        );
        if Self::run_cmd(&az_cmd).is_err() {
            error!("delete_mhsm(): error deleting mhsm");
        }

        // let az_cmd = format!("az keyvault purge --hsm-name {mhsm_name} --location
        // {AZURE_LOCATION}");
        let az_cmd = format!("az keyvault purge --name {mhsm_name} --location {AZURE_LOCATION}");
        if Self::run_cmd(&az_cmd).is_err() {
            error!("delete_mhsm(): error purging key vault");
        }

        Ok(())
    }

    // ------------------------ Azure Attestation ------------------------------

    pub fn create_aa(aa_name: &str) -> Result<()> {
        info!("create_aa(): creating attestation service (name={aa_name})");
        let az_cmd = format!(
            "az attestation create --name {aa_name} -g {AZURE_RESOURCE_GROUP} \
            --location {AZURE_LOCATION}"
        );
        Self::run_cmd_get_output(&az_cmd)?;
        Ok(())
    }

    pub fn delete_aa(aa_name: &str) -> Result<()> {
        let az_cmd = format!(
            "az attestation delete --name {aa_name} \
            --resource-group {AZURE_RESOURCE_GROUP} --yes"
        );
        if Self::run_cmd(&az_cmd).is_err() {
            error!("delete_aa(): error deleting azure attestation provider");
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Ansible Provisioning Functions
    // -------------------------------------------------------------------------

    // WARNING: this method assumes that the VM names are prefixed with the
    // VM deployment group name
    // WARNING: this method assumes that the inventory name is the same than
    // the yaml file containing the tasks
    pub fn provision_with_ansible(
        vm_deployment: &str,
        inventory_name: &str,
        extra_vars: Option<HashMap<&str, &str>>,
    ) -> Result<()> {
        let mut inventory_file = Env::ansible_root().join("inventory");
        fs::create_dir_all(&inventory_file)?;
        inventory_file.push("vms.ini");

        info!(
            "provision_with_ansible(): provisioning VM deployment (name={vm_deployment}, inv_file={}, extra_vars={extra_vars:?})",
            inventory_file.display()
        );

        let mut inventory = vec![format!("[{inventory_name}]")];
        let vms: Vec<Value> = Self::list_all_resources("vm", Some(vm_deployment))?;
        for vm in vms {
            let name = vm["name"].as_str().unwrap();
            let ip = Self::get_vm_ip(name)?;
            inventory.push(format!(
                "{} ansible_host={} ansible_user={}",
                name, ip, AZURE_USERNAME
            ));
        }

        fs::write(&inventory_file, inventory.join("\n") + "\n")
            .expect("Failed to write inventory file");

        info!(
            "provision_with_ansible(): generated ansible inventory:\n{}",
            inventory.join("\n")
        );

        let ansible_cmd = format!(
            "ANSIBLE_CONFIG={} ansible-playbook -i {} {} {}",
            Env::ansible_root().join("ansible.cfg").to_str().unwrap(),
            inventory_file.to_str().unwrap(),
            Env::ansible_root()
                .join(format!("{inventory_name}.yaml"))
                .to_str()
                .unwrap(),
            match extra_vars {
                Some(val) => {
                    let json = serde_json::to_string(&val).unwrap();
                    format!("-e '{json}'")
                }
                None => "".to_string(),
            }
        );
        debug!("provision_with_ansible(): running ansible cmd: {ansible_cmd}");
        Self::run_cmd_check_status(&ansible_cmd, "failed to run ansible playbook")
    }

    pub fn run_scp_cmd(src_path: &str, dst_path: &str) -> Result<()> {
        info!(
            "run_scp_cmd(): scp-ing file from '{}' to '{}'",
            src_path, dst_path
        );

        let (vm_name, local_path, remote_path, to_vm) = if let Some(rest) =
            src_path.strip_prefix(':')
        {
            return Err(anyhow::anyhow!(
                "Invalid source path, missing VM name before ':' in '{}'",
                rest
            ));
        } else if let Some(rest) = dst_path.strip_prefix(':') {
            return Err(anyhow::anyhow!(
                "Invalid destination path, missing VM name before ':' in '{}'",
                rest
            ));
        } else if let Some((vm, path)) = src_path.split_once(':') {
            (vm, dst_path, path, false) // from_vm
        } else if let Some((vm, path)) = dst_path.split_once(':') {
            (vm, src_path, path, true) // to_vm
        } else {
            return Err(anyhow::anyhow!(
                "Could not determine SCP direction. One path must be of the form <vm_name>:<path>. Got src='{}', dst='{}'",
                src_path,
                dst_path
            ));
        };

        if to_vm {
            if let Some(parent_str) = std::path::Path::new(remote_path)
                .parent()
                .and_then(|p| p.to_str())
                .filter(|s| !s.is_empty())
            {
                info!(
                    "run_scp_cmd(): creating remote directory '{}' on VM '{}'",
                    parent_str, vm_name
                );
                let mkdir_cmd = vec![
                    "mkdir".to_string(),
                    "-p".to_string(),
                    parent_str.to_string(),
                ];
                Self::run_cmd_in_vm(vm_name, &mkdir_cmd, None)?;
            }
        } else if let Some(parent) = std::path::Path::new(local_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            debug!(
                "run_scp_cmd(): creating local directory '{}'",
                parent.display()
            );
            std::fs::create_dir_all(parent)?;
        }

        let ip = Self::get_vm_ip(vm_name)?;
        let remote_target = format!("{}@{}:{}", AZURE_USERNAME, ip, remote_path);

        let (final_src, final_dst) = if to_vm {
            (local_path, remote_target.as_str())
        } else {
            (remote_target.as_str(), local_path)
        };

        let ssh_priv_key = shellexpand::tilde(AZURE_SSH_PRIV_KEY).into_owned();
        let cmd = format!(
            "scp -i {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {} {}",
            ssh_priv_key, final_src, final_dst,
        );

        debug!("run_scp_cmd(): running scp command: {}", cmd);
        Self::run_cmd_check_status(&cmd, "failed to run scp command")?;

        Ok(())
    }

    pub fn build_scp_command(vm_name: &str) -> Result<String> {
        Ok(format!(
            "scp -i {AZURE_SSH_PRIV_KEY} {AZURE_USERNAME}@{}",
            Self::get_vm_ip(vm_name)?,
        ))
    }

    pub fn build_ssh_command(vm_name: &str) -> Result<String> {
        Ok(format!(
            "ssh -A -i {AZURE_SSH_PRIV_KEY} {AZURE_USERNAME}@{}",
            Self::get_vm_ip(vm_name)?,
        ))
    }

    pub fn run_cmd_in_vm(vm_name: &str, cmd: &[String], cwd: Option<&str>) -> Result<()> {
        let mut full_cmd = String::new();
        if let Some(working_dir) = cwd {
            full_cmd.push_str(&format!("cd {} && ", working_dir));
        }
        full_cmd.push_str(&cmd.join(" "));

        let mut ssh_cmd = Self::build_ssh_command(vm_name)?;
        ssh_cmd.push_str(" \"");
        ssh_cmd.push_str(&full_cmd);
        ssh_cmd.push('\"');

        debug!("run_cmd_in_vm(): running cmd: {}", ssh_cmd);

        Self::run_cmd_check_status(&ssh_cmd, "failed to run command in vm")
    }
}

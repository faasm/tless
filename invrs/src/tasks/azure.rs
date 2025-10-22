use crate::env::Env;
use base64::Engine;
use log::info;
use serde_json::Value;
use shellexpand;
use std::{fs, collections::HashMap, process::Command, process::ExitStatus};

const AZURE_RESOURCE_GROUP: &str = "faasm";
const AZURE_USERNAME: &str = "tless";
const AZURE_LOCATION: &str = "eastus";

const AZURE_SSH_PRIV_KEY: &str = "~/.ssh/id_rsa";
const AZURE_SSH_PUB_KEY: &str = "~/.ssh/id_rsa.pub";

const AZURE_SGX_VM_IMAGE: &str = "Canonical:ubuntu-24_04-lts:server:latest";
const AZURE_SNP_CC_VM_SIZE: &str =
    "/CommunityGalleries/cocopreview-91c44057-c3ab-4652-bf00-9242d5a90170/Images/ubu2204-snp-host-upm/Versions/latest";

//  Specifies order in which to delete resource types
const RESOURCE_TYPE_PRECEDENCE: [&str; 4] = [
    "Microsoft.Network/networkInterfaces",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/virtualNetworks",
    "Microsoft.Network/publicIpAddresses",
];

#[derive(Debug)]
pub struct Azure {}

impl Azure {
    // -------------------------------------------------------------------------
    // Misc Helpers
    // -------------------------------------------------------------------------

    #[allow(dead_code)]
    fn create_self_signed_cert(key_out_path: &str, cert_out_path: &str) {
        let openssl_cmd = format!(
            "openssl req -newkey rsa:2048 -nodes -keyout {key_out_path} \
            -subj \"/O=TLess/OU=TLess/CN=TLess-mhsm-cert\" \
            -x509 -days 365 -out {cert_out_path}"
        );
        Self::run_cmd_check_status(
            &openssl_cmd,
            "error generating self-signed openssl certificate",
        );
    }

    // -------------------------------------------------------------------------
    // Command Helpers
    // -------------------------------------------------------------------------

    fn run_cmd(cmd: &str, error_msg: &str) -> ExitStatus {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .unwrap_or_else(|_| panic!("invrs: {}", error_msg))
    }

    fn run_cmd_check_status(cmd: &str, error_msg: &str) {
        let status = Self::run_cmd(cmd, error_msg);

        if !status.success() {
            panic!("invrs: {error_msg}");
        }
    }

    fn run_cmd_get_output(cmd: &str, error_msg: &str) -> String {
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .unwrap_or_else(|_| panic!("invrs: {}", error_msg));

        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout.trim().to_string()
    }

    // -------------------------------------------------------------------------
    // Azure Helpers
    // -------------------------------------------------------------------------

    /// Activate a managed HSM by providing three certificates for the security
    /// domain
    #[allow(dead_code)]
    fn activate_managed_hsm(mhsm_name: &str) {
        let key_dir = Env::proj_root().join("azure").join("keys");
        fs::create_dir_all(&key_dir).expect("invrs: failed to create key directory");

        Self::create_self_signed_cert(
            key_dir.join("cert0.key").to_str().unwrap(),
            key_dir.join("cert0.cert").to_str().unwrap(),
        );
        Self::create_self_signed_cert(
            key_dir.join("cert1.key").to_str().unwrap(),
            key_dir.join("cert1.cert").to_str().unwrap(),
        );
        Self::create_self_signed_cert(
            key_dir.join("cert2.key").to_str().unwrap(),
            key_dir.join("cert2.cert").to_str().unwrap(),
        );

        let key_dir_str = key_dir.to_str().unwrap();
        let az_cmd = format!(
            "az keyvault security-domain download --hsm-name {mhsm_name} \
            --sd-wrapping-keys {key_dir_str}/cert0.cert {key_dir_str}/cert1.cert \
            {key_dir_str}/cert2.cert --sd-quorum 2 \
            --security-domain-file {key_dir_str}/{mhsm_name}-sd.json"
        );
        Self::run_cmd_check_status(&az_cmd, "error activating managed HSM");
    }

    fn delete_resource(name: &str, resource_type: &str) {
        info!("deleting resource: {name} (type: {resource_type})");

        let cmd = format!(
            "az resource delete --resource-group {AZURE_RESOURCE_GROUP} \
            --name {name} --resource-type {resource_type}"
        );
        // Some delete operations may fail sometimes, we still want to make
        // progress
        Self::run_cmd(&cmd, "failed to delete resource");
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

    pub fn get_aa_attest_uri(aa_name: &str) -> String {
        let az_cmd = format!(
            "az attestation show --name {aa_name} --resource-group {AZURE_RESOURCE_GROUP} \
            --query attestUri --output tsv"
        );
        Self::run_cmd_get_output(&az_cmd, "error getting atestation uri")
    }

    pub fn get_key_uri(kv_name: &str, key_name: &str) -> String {
        let az_cmd = format!(
            "az keyvault show --vault-name {kv_name} --name {key_name} \
            --query \"key.kid\" --output tsv"
        );
        Self::run_cmd_get_output(&az_cmd, "error getting key id from key vault")
    }

    fn get_managed_identity_oid(vm_name: &str) -> String {
        let subscription_id = Self::get_subscription_id();
        let resource_id = format!(
            "/subscriptions/{subscription_id}/resourceGroups\
            /{AZURE_RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines\
            /{vm_name}"
        );

        let az_cmd = format!(
            "az resource show --ids {resource_id} \
            --query \"identity.principalId\" -o tsv"
        );
        Self::run_cmd_get_output(&az_cmd, "error getting managed resource id")
    }

    fn get_subscription_id() -> String {
        let az_cmd = "az account show --query id --output tsv";
        Self::run_cmd_get_output(az_cmd, "error getting subscription id")
    }

    pub fn get_vm_ip(vm_name: &str) -> String {
        let az_cmd = format!("az vm list-ip-addresses -n {vm_name} -g {AZURE_RESOURCE_GROUP}");
        let stdout = Self::run_cmd_get_output(&az_cmd, "error getting VM ip");
        let json: Vec<Value> =
            serde_json::from_str(&stdout).expect("invrs: error: invalid JSON from az command");

        json[0]["virtualMachine"]["network"]["publicIpAddresses"][0]["ipAddress"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// List all resources of type `resource` beginning with prefix `prefix
    fn list_all_resources(resource: &str, prefix: Option<&str>) -> Vec<Value> {
        let az_cmd = format!("az {resource} list --resource-group {AZURE_RESOURCE_GROUP}");
        let stdout = Self::run_cmd_get_output(&az_cmd, "error listing resources");
        let json: Vec<Value> =
            serde_json::from_str(&stdout).expect("invrs: error: invalid JSON from az command");

        // Filter by name prefix
        if let Some(prefix_str) = prefix {
            json.into_iter()
                .filter(|v| {
                    v["name"]
                        .as_str()
                        .map(|name| name.starts_with(prefix_str))
                        .unwrap_or(false)
                })
                .collect()
        } else {
            json
        }
    }

    /// Open a list of ports in a VM. Note that, given that we do not set
    /// priorities in the port rules, trying to run the same method twice
    /// on the same VM will fail. Hence why we support passing a list of ports
    /// so that the operation is only done once.
    pub fn open_vm_ports(vm_name: &str, ports: &[usize]) {
        let port_str = ports
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let az_cmd = format!(
            "az vm open-port --resource-group {AZURE_RESOURCE_GROUP} \
            --name {vm_name} --port {port_str}"
        );
        Self::run_cmd_check_status(&az_cmd, "error opening port on VM");
    }

    /// Perform an arbitrary operation `op` on a VM with name `name`. We can
    /// pass additional arguments via extra_args: `["--yes", "--no"]`
    fn vm_op(op: &str, name: &str, extra_args: &[&str]) {
        info!("performing {} on vm {}", op, name);

        let extra = extra_args.join(" ");
        let cmd = format!(
            "az vm {} --resource-group {} --name {} {}",
            op, AZURE_RESOURCE_GROUP, name, extra
        );
        Self::run_cmd_check_status(&cmd, "failed to execute vm_op");
    }

    // -------------------------------------------------------------------------
    // Create/Delete Azure Resources
    // -------------------------------------------------------------------------

    // ------------------------------ SGX VMs ---------------------------------

    // SGXv2 VMs in Azure are in the DCdsv3 family:
    // https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcdsv3-series
    pub fn create_sgx_vm(vm_name: &str, vm_sku: &str) {
        info!("creating sgx vm: {vm_name} (sku: {vm_sku})");
        let az_cmd = format!(
            "az vm create --resource-group {AZURE_RESOURCE_GROUP} \
            --name {vm_name} --admin-username {AZURE_USERNAME} --location \
            {AZURE_LOCATION} --ssh-key-value {AZURE_SSH_PUB_KEY} \
            --image {AZURE_SGX_VM_IMAGE} --size {vm_sku} --os-disk-size-gb 128 \
            --public-ip-sku Standard --os-disk-delete-option delete \
            --data-disk-delete-option delete --nic-delete-option delete"
        );
        Self::run_cmd(&az_cmd, "error deploying sgx vm");
    }

    pub fn delete_sgx_vm(vm_name: &str) {
        // First delete VM
        Self::vm_op("delete", vm_name, &["--yes"]);

        // Then delete all attached resources
        let all_resources = Self::list_all_resources("resource", Some(vm_name));
        Self::delete_resources(all_resources);
    }

    // ------------------------------ SNP cVMs ---------------------------------

    // Readily-available cVMs (i.e. SNP guests) in Azure are in the DCasv5 series:
    // https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcasv5-series
    pub fn create_snp_guest(vm_name: &str, vm_sku: &str) {
        info!("creating snp guest: {vm_name} (sku: {vm_sku})");

        let parameter_file = Env::proj_root()
            .join("azure")
            .join("snp_guest_parameters.json");
        let template_file = Env::proj_root()
            .join("azure")
            .join("snp_guest_template.json");
        let cloud_init_file = Env::proj_root()
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
        Self::run_cmd(&az_cmd, "error deploying snp guest");
    }

    pub fn delete_snp_guest(vm_name: &str) {
        info!("deleting snp guest: {vm_name}");

        // First delete VM
        Self::vm_op("delete", vm_name, &["--yes"]);

        // Then delete all attached resources
        let all_resources = Self::list_all_resources("resource", Some(vm_name));
        Self::delete_resources(all_resources);

        let az_cmd = format!("az deployment group delete -g {AZURE_RESOURCE_GROUP} -n {vm_name}",);
        Self::run_cmd(&az_cmd, "error deleting snp guest");
    }

    // ------------------------------ SNP cc-VMs -------------------------------

    // SNP child-chapable VMs are regular VMs that support creating SNP
    // protected child VMs. Note that the parent VM is _not_ running in an SNP
    // guest, only the child
    // https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcasccv5-series
    pub fn create_snp_cc_vm(vm_name: &str, vm_sku: &str) {
        info!("creating snp cc-vm: {vm_name} (sku: {vm_sku})");
        let az_cmd = format!(
            "az vm create --resource-group {AZURE_RESOURCE_GROUP} \
            --name {vm_name} --admin-username {AZURE_USERNAME} --location \
            {AZURE_LOCATION} --ssh-key-value {AZURE_SSH_PUB_KEY} \
            --image {AZURE_SNP_CC_VM_SIZE} --size {vm_sku} --os-disk-size-gb 128 \
            --accelerated-networking true --accept-term"
        );
        Self::run_cmd(&az_cmd, "error deploying snp cc-vm");
    }

    pub fn delete_snp_cc_vm(vm_name: &str) {
        // First delete VM
        Self::vm_op("delete", vm_name, &["--yes"]);

        // Then delete all attached resources
        let all_resources = Self::list_all_resources("resource", Some(vm_name));
        Self::delete_resources(all_resources);
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
    pub fn create_mhsm(mhsm_name: &str, vm_name: &str, key_name: &str) {
        info!("creating managed hsm: {mhsm_name} (paired with vm: {vm_name})");

        // Create managed HSM
        /* FIXME: allocating a mHSM can take between 15 to 30'. To avoid this,
         * and for the time being, we run the tests with an AKV with the
         * `premium` SKU.
        let az_cmd = "az ad signed-in-user show --query id -o tsv";
        let oid = Self::run_cmd_get_output(az_cmd, "error showing user id");
        let az_cmd = format!(
            "az keyvault create --hsm-name {mhsm_name} \
            --resource-group {AZURE_RESOURCE_GROUP} \
            --location {AZURE_LOCATION} --administrators {} \
            --enable-rbac-authorization false \
            --retention-days 7", oid.trim());
        */
        let az_cmd = format!(
            "az keyvault create --name {mhsm_name} \
            --resource-group {AZURE_RESOURCE_GROUP} --sku premium \
            --enable-rbac-authorization false"
        );
        Self::run_cmd_check_status(&az_cmd, "error creating managed-hsm");

        // FIXME: see above
        // Activate managed HSM
        // Self::activate_managed_hsm(&mhsm_name);

        // Give our cVM key-release access in this managed HSM
        let az_cmd = format!(
            "az keyvault set-policy --name {mhsm_name} \
            --object-id {} --key-permissions release",
            Self::get_managed_identity_oid(vm_name)
        );
        Self::run_cmd_check_status(&az_cmd, "error granting cVM access to mHSM");

        // Create an exportable key with an attached key-release policy. Given
        // that we use a managed HSM, we must select a key type with the -HSM
        // extension:
        // https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys
        let az_cmd = format!(
            "az keyvault key create --exportable true --vault-name {mhsm_name} \
            --kty RSA-HSM --name {key_name} --policy {}",
            Env::proj_root()
                .join("azure")
                .join("mhsm_skr_policy.json")
                .display()
        );
        Self::run_cmd_check_status(&az_cmd, "error creating key with release policy");
    }

    pub fn delete_mhsm(mhsm_name: &str) {
        /* FIXME: see above
        let az_cmd = format!(
            "az keyvault delete --hsm-name {mhsm_name} \
            --resource-group {AZURE_RESOURCE_GROUP}");
        */
        let az_cmd = format!(
            "az keyvault delete --name {mhsm_name} \
            --resource-group {AZURE_RESOURCE_GROUP}"
        );
        Self::run_cmd(&az_cmd, "error deleting mhsm");

        // let az_cmd = format!("az keyvault purge --hsm-name {mhsm_name} --location {AZURE_LOCATION}");
        let az_cmd = format!("az keyvault purge --name {mhsm_name} --location {AZURE_LOCATION}");
        Self::run_cmd(&az_cmd, "error deleting mhsm");
    }

    // ------------------------ Azure Attestation ------------------------------

    pub fn create_aa(aa_name: &str) {
        let az_cmd = format!(
            "az attestation create --name {aa_name} -g {AZURE_RESOURCE_GROUP} \
            --location {AZURE_LOCATION}"
        );
        Self::run_cmd_check_status(&az_cmd, "error creating attestation provider");
    }

    pub fn delete_aa(aa_name: &str) {
        let az_cmd = format!(
            "az attestation delete --name {aa_name} \
            --resource-group {AZURE_RESOURCE_GROUP} --yes"
        );
        Self::run_cmd(&az_cmd, "error deleting attestation provider");
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
    ) {
        let mut inventory_file = Env::ansible_root().join("inventory");
        fs::create_dir_all(&inventory_file).expect("invrs: failed to create inventory directory");
        inventory_file.push("vms.ini");

        let mut inventory = vec![format!("[{inventory_name}]")];

        let vms: Vec<Value> = Self::list_all_resources("vm", Some(vm_deployment));
        for vm in vms {
            let name = vm["name"].as_str().unwrap();
            let ip = Self::get_vm_ip(name);
            inventory.push(format!(
                "{} ansible_host={} ansible_user={}",
                name, ip, AZURE_USERNAME
            ));
        }

        fs::write(&inventory_file, inventory.join("\n") + "\n")
            .expect("Failed to write inventory file");

        info!("generated ansible inventory:\n{}", inventory.join("\n"));

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
                },
                None => "".to_string(),
            }
        );
        println!("FOO: {ansible_cmd}");
        Self::run_cmd_check_status(&ansible_cmd, "failed to run ansible playbook");
    }

    pub fn build_scp_command(vm_name: &str) -> String {
        format!(
            "scp -i {AZURE_SSH_PRIV_KEY} {AZURE_USERNAME}@{}",
            Self::get_vm_ip(vm_name),
        )
    }
    pub fn build_ssh_command(vm_name: &str) {
        println!(
            "ssh -A -i {AZURE_SSH_PRIV_KEY} {AZURE_USERNAME}@{}",
            Self::get_vm_ip(vm_name),
        )
    }
}

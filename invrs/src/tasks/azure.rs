use base64::Engine;
use crate::env::Env;
use log::info;
use serde_json::Value;
use shellexpand;
use std::{fs, process::Command};

const AZURE_RESOURCE_GROUP: &str = "faasm";

const AZURE_SNP_VM_DEPLOYMENT: &str = "tless-snp-deployment";
const AZURE_SNP_VM_ADMIN: &str = "tless";
const AZURE_SNP_VM_IMAGE: &str = "Canonical:ubuntu-24_04-lts:server:latest";
const AZURE_SNP_VM_LOCATION: &str = "eastus";
const AZURE_SNP_VM_NAME: &str = "tless-snp-guest";
const AZURE_SNP_VM_SSH_PRIV_KEY: &str = "~/.ssh/id_rsa";
const AZURE_SNP_VM_SSH_PUB_KEY: &str = "~/.ssh/id_rsa.pub";

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
    fn list_all(resource: &str, prefix: Option<&str>) -> Vec<Value> {
        let az_cmd = format!("az {resource} list -g {AZURE_RESOURCE_GROUP}");

        let output = Command::new("sh")
            .arg("-c")
            .arg(az_cmd)
            .output()
            .expect("invrs: error listing resources");

        let stdout =
            String::from_utf8(output.stdout).expect("invrs: error: invalid UTF-8 from az command");
        let json: Vec<Value> =
            serde_json::from_str(&stdout).expect("invrs: error: invalid JSON from az command");
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

    fn delete_resource(name: &str, resource_type: &str) {
        info!("deleting resource: {name} (type: {resource_type})");

        let cmd = format!(
            "az resource delete -g {AZURE_RESOURCE_GROUP} --name {name} --resource-type {resource_type}",
        );
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .expect("invrs: error: failed to delete resource");
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

    fn vm_op(op: &str, name: &str, extra_args: &[&str]) {
        info!("performing {} on vm {}", op, name);

        let extra = extra_args.join(" ");
        let cmd = format!(
            "az vm {} --resource-group {} --name {} {}",
            op, AZURE_RESOURCE_GROUP, name, extra
        );
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .expect("invrs: error: failed to execute vm_op");
    }

    fn vm_ip(vm_name: &str) -> String {
        let az_cmd = format!("az vm list-ip-addresses -n {vm_name} -g {AZURE_RESOURCE_GROUP}");

        let output = Command::new("sh")
            .arg("-c")
            .arg(az_cmd)
            .output()
            .expect("invrs: error getting VM ip");
        let stdout =
            String::from_utf8(output.stdout).expect("invrs: error: invalid UTF-8 from az command");
        let json: Vec<Value> =
            serde_json::from_str(&stdout).expect("invrs: error: invalid JSON from az command");

        json[0]["virtualMachine"]["network"]["publicIpAddresses"][0]["ipAddress"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub fn create_snp_guest() {
        info!("creating snp guest: {AZURE_SNP_VM_NAME}");

        let parameter_file = Env::proj_root().join("azure").join("snp_guest_parameters.json");
        let template_file = Env::proj_root().join("azure").join("snp_guest_template.json");
        let cloud_init_file = Env::proj_root().join("azure").join("snp_guest_cloud-init.txt");

        let cinit_content = fs::read(cloud_init_file).expect("error: reading cloud-init file");
        let custom_data = base64::engine::general_purpose::STANDARD.encode(cinit_content);

        let pub_key = fs::read_to_string(shellexpand::tilde(AZURE_SNP_VM_SSH_PUB_KEY).into_owned())
            .expect("invrs: error loading ssh pub key");
        let az_cmd = format!(
            "az deployment group create -g {AZURE_RESOURCE_GROUP} -n {AZURE_SNP_VM_DEPLOYMENT} --template-file {} -p {} -p vmName={AZURE_SNP_VM_NAME} -p adminPasswordOrKey='{pub_key}' -p customData='{custom_data}'",
            template_file.display(),
            parameter_file.display()
        );
        Command::new("sh")
            .arg("-c")
            .arg(az_cmd)
            .status()
            .expect("invrs: error deploying snp guest on azure");

        // Also open port 22, which seems to be closed by default in this cVMs
        let az_cmd =
            format!("az vm open-port -g {AZURE_RESOURCE_GROUP} -n {AZURE_SNP_VM_NAME} --port 22");
        Command::new("sh")
            .arg("-c")
            .arg(az_cmd)
            .status()
            .expect("invrs: error opening port on vm");
    }

    pub fn provision_snp_guest() {
        let mut inventory_file = Env::ansible_root().join("inventory");
        fs::create_dir_all(&inventory_file).expect("invrs: failed to create inventory directory");
        inventory_file.push("vms.ini");

        let mut inventory = vec!["[snpguest]".to_string()];

        let vms: Vec<Value> = Self::list_all("vm", Some(AZURE_SNP_VM_NAME));
        for vm in vms {
            let name = vm["name"].as_str().unwrap();
            let ip = Self::vm_ip(name);
            inventory.push(format!(
                "{} ansible_host={} ansible_user={}",
                name, ip, AZURE_SNP_VM_ADMIN
            ));
        }

        fs::write(&inventory_file, inventory.join("\n") + "\n")
            .expect("Failed to write inventory file");

        info!("generated ansible inventory:\n{}", inventory.join("\n"));

        let playbook = Env::ansible_root().join("snp_vm.yaml");
        Command::new("ansible-playbook")
            .arg("-i")
            .arg(inventory_file)
            .arg(playbook)
            .status()
            .expect("error: failed to run ansible playbook");
    }

    pub fn build_ssh_command() {
        println!(
            "ssh -A -i {AZURE_SNP_VM_SSH_PRIV_KEY} {AZURE_SNP_VM_ADMIN}@{}",
            Self::vm_ip(AZURE_SNP_VM_NAME),
        )
    }

    pub fn delete_snp_guest() {
        info!("deleting snp guest: {AZURE_SNP_VM_NAME}");

        // First delete VM
        Self::vm_op("delete", AZURE_SNP_VM_NAME, &["--yes"]);

        // Then delete all attached resources
        let all_resources = Self::list_all("resource", Some(AZURE_SNP_VM_NAME));
        Self::delete_resources(all_resources);

        // Lastly delete deployment group
        let az_cmd = format!(
            "az deployment group delete -g {AZURE_RESOURCE_GROUP} -n {AZURE_SNP_VM_DEPLOYMENT}",
        );
        Command::new("sh")
            .arg("-c")
            .arg(az_cmd)
            .status()
            .expect("invrs: error deleting snp guest on azure");
    }
}

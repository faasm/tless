use crate::{
    env::Env,
    tasks::{
        accless::Accless,
        applications::{self, Applications},
        attestation_service::AttestationService,
        azure::{self, Azure, AzureUtilsCommand},
        cvm::{self, Component, parse_host_guest_path},
        dev::Dev,
        docker::{Docker, DockerContainer},
        experiments::{self, E2eSubScommand, Experiment, UbenchSubCommand},
        s3::S3,
    },
};
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::info;
use std::{collections::HashMap, path::PathBuf, process};

pub mod attestation_service;
pub mod env;
pub mod tasks;

#[derive(Parser)]
struct Cli {
    // The name of the task to execute
    #[clap(subcommand)]
    task: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build or test the main Accless library
    Accless {
        #[command(subcommand)]
        accless_command: AcclessCommand,
    },
    /// Build or test the Accless applications
    Applications {
        #[command(subcommand)]
        applications_command: ApplicationsCommand,
    },
    /// Provision SGX or SNP capable VMs on Azure
    Azure {
        #[command(subcommand)]
        az_command: AzureCommand,
    },
    /// Development-related tasks
    Dev {
        #[command(subcommand)]
        dev_command: DevCommand,
    },
    /// Run evaluation experiments and plot results
    Experiments {
        #[command(subcommand)]
        experiments_command: Experiment,
    },
    /// Interact with an S3 (MinIO server)
    S3 {
        #[command(subcommand)]
        s3_command: S3Command,
    },
    /// Build and run the attestation service
    AttestationService {
        #[command(subcommand)]
        attestation_service_command: AttestationServiceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AttestationServiceCommand {
    /// Build the attestation service
    Build {},
    /// Run the attestation service
    Run {
        /// Directory where to look-for and store TLS certificates.
        #[arg(long)]
        certs_dir: Option<PathBuf>,
        /// Port to bind the server to.
        #[arg(long)]
        port: Option<u16>,
        /// URL to fetch SGX platform collateral information.
        #[arg(long)]
        sgx_pccs_url: Option<PathBuf>,
        /// Whether to overwrite the existing TLS certificates (if any).
        #[arg(long)]
        force_clean_certs: bool,
        /// Run the attestation service in mock mode, skipping quote
        /// verification.
        #[arg(long, default_value_t = false)]
        mock: bool,
        /// Rebuild the attestation service before running.
        #[arg(long, default_value_t = false)]
        rebuild: bool,
        /// Run the attestation service in the background, storing its PID.
        #[arg(long, default_value_t = false)]
        background: bool,
        /// Overwrite the public IP of the attestation service.
        #[arg(long)]
        overwrite_external_ip: Option<String>,
    },
    /// Stop a running attestation service (started with --background).
    Stop {},
    Health {
        /// URL of the attestation service
        #[arg(long)]
        url: Option<String>,
        /// Path to the attestation service's public certificate PEM file
        #[arg(long)]
        cert_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum DagCommand {
    Upload {
        /// Name of the application to upload
        name: String,
        /// Path to the YAML file describing the workflow
        yaml_path: String,
    },
}

#[derive(Debug, Subcommand)]
enum DevCommand {
    /// Bump the code version
    BumpVersion {
        #[arg(long)]
        major: bool,
        #[arg(long)]
        minor: bool,
        #[arg(long)]
        patch: bool,
    },
    /// Run code formatting: clang-format, cargo fmt, and cargo clippy
    FormatCode {
        /// Dry-run and report errors if not formatted well
        #[arg(long)]
        check: bool,
    },
    /// Tag the current commit with the version from the VERSION file
    Tag {
        /// Force push the tag
        #[arg(long)]
        force: bool,
    },
    /// Build and run commands in the work-on container image
    Docker {
        #[command(subcommand)]
        docker_command: DockerCommand,
    },
    /// Build and run commands in an SNP-enabled cVM (requires SNP hardware)
    Cvm {
        #[command(subcommand)]
        cvm_command: CvmCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CvmCommand {
    /// Run a command inside the cVM.
    Run {
        #[arg(last = true)]
        cmd: Vec<String>,
        /// Optional: SCP files into the cVM.
        /// Specify as <HOST_PATH>:<GUEST_PATH>. Can be repeated.
        #[arg(long, value_name = "HOST_PATH:GUEST_PATH", value_parser = parse_host_guest_path)]
        scp_file: Vec<(PathBuf, PathBuf)>,
        /// Set the working directory inside the container
        #[arg(long)]
        cwd: Option<PathBuf>,
    },
    /// Configure the cVM image by building and installing the different
    /// components.
    Setup {
        #[arg(long)]
        clean: bool,
        #[arg(long)]
        component: Option<Component>,
    },
    /// Get an interactive shell inside the cVM.
    Cli {
        /// Set the working directory inside the container
        #[arg(long)]
        cwd: Option<PathBuf>,
    },
    /// SCP a file to/from the cVM.
    Scp {
        /// Path to the source file. To indicate a path inside the cVM,
        /// prefix it with `cvm:`.
        src_path: String,
        /// Path to the destination file. To indicate a path inside the cVM,
        /// prefix it with `cvm:`.
        dst_path: String,
    },
}

#[derive(Debug, Subcommand)]
enum DockerCommand {
    /// Build one of Accless' docker containers. Run build --help to see the
    /// possibe options
    Build {
        /// Container image to build.
        ctr: Vec<DockerContainer>,
        #[arg(long)]
        push: bool,
        #[arg(long)]
        nocache: bool,
    },
    /// Build all Accless docker containers
    BuildAll {
        #[arg(long)]
        push: bool,
        #[arg(long)]
        nocache: bool,
    },
    /// Get a CLI interface to the experiments container
    Cli {
        /// Connect the container to the host's network
        #[arg(long)]
        net: bool,
    },
    /// Run a command inside the experiments container
    Run {
        cmd: Vec<String>,
        /// Mount the current directory to /code/tless
        #[arg(long)]
        mount: bool,
        /// Set the working directory inside the container
        #[arg(long)]
        cwd: Option<String>,
        /// Set environment variables inside the container
        #[arg(long, value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Connect the container to the host's network
        #[arg(long)]
        net: bool,
        /// Capture the standard output of the command
        #[arg(long)]
        capture_output: bool,
    },
}

#[derive(Debug, Subcommand)]
enum S3Command {
    /// Clear a given bucket in an S3 server
    ClearBucket {
        #[arg(long, default_value = "tless")]
        bucket_name: String,
    },
    /// Clear a sub-tree in an S3 bucket indicated by a prefix
    ClearDir {
        #[arg(long, default_value = "tless")]
        bucket_name: String,
        #[arg(long)]
        prefix: String,
    },
    /// Download a directory from S3 to the host
    GetDir {
        #[arg(long, default_value = "tless")]
        bucket_name: String,
        #[arg(long)]
        s3_path: String,
        #[arg(long)]
        host_path: String,
    },
    /// Clear a sub-tree in an S3 bucket indicated by a prefix
    GetKey {
        #[arg(long, default_value = "tless")]
        bucket_name: String,
        #[arg(long)]
        key: String,
    },
    GetUrl {
        /// Whereas we are using S3 with 'faasm' or 'knative'
        system: String,
    },
    /// List all buckets in an S3 server
    ListBuckets {},
    /// List all keys in an S3 bucket
    ListKeys {
        /// Name of the bucket
        #[arg(long, default_value = "tless")]
        bucket_name: String,
        /// Prefix
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Upload a directory to S3
    UploadDir {
        /// Name of the bucket to store files in
        #[arg(long, default_value = "tless")]
        bucket_name: String,
        /// Host path to upload files from
        #[arg(long)]
        host_path: String,
        /// Path in the S3 server to store files to
        #[arg(long)]
        s3_path: String,
    },
    /// Upload an object to S3
    UploadKey {
        /// Name of the bucket to store files in
        #[arg(long, default_value = "tless")]
        bucket_name: String,
        /// Host path of the file to upload
        #[arg(long)]
        host_path: String,
        /// Path in the S3 server for the uploaded file
        #[arg(long)]
        s3_path: String,
    },
}

#[derive(Debug, Subcommand)]
enum AzureCommand {
    /// Deploy an environment witn an SNP cVM and our CP-ABE based secret-
    /// release logic, an instance of our attestation service, and
    /// an instance of microsft's attestation service
    Accless {
        #[command(subcommand)]
        az_sub_command: AzureSubCommand,
    },
    /// Deploy an instance of Accless' attestation service
    AttestationService {
        #[command(subcommand)]
        az_sub_command: AzureSubCommand,
    },
    /// Deploy an environment with an SNP cVM and a managed HSM acting as
    /// relying party to perform secure key release (SKR)
    ManagedHSM {
        #[command(subcommand)]
        az_sub_command: AzureSubCommand,
    },
    /// Deploy our port of Faasm that can run Faaslets inside SGX enclaves
    /// (for the time being, we deploy Faasm using docker compose, we could
    /// consider moving to AKS, or a single-node K8s)
    SgxFaasm {
        #[command(subcommand)]
        az_sub_command: AzureSubCommand,
    },
    /// Deploy our port of Knative that can run KServices inside SNP cVMs
    SnpKnative {
        #[command(subcommand)]
        az_sub_command: AzureSubCommand,
    },
    /// Deploy an environment with two SNP cVMs, one running Trustee as a
    /// relying party, and the other one requesting a secure key release (SKR)
    Trustee {
        #[command(subcommand)]
        az_sub_command: AzureSubCommand,
    },
    /// Utility azure-related commands.
    Utils {
        #[command(subcommand)]
        az_utils_command: AzureUtilsCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AzureSubCommand {
    /// Create an Azure resource
    Create {},
    /// Provision Azure resource using Ansible
    Provision {},
    /// Get a SSH command into the Azure resource (if applicable)
    Ssh {},
    /// Delete the Azure resource
    Delete {},
}

#[derive(Debug, Subcommand)]
enum AcclessCommand {
    /// Build the Accless C++ library
    Build {
        #[arg(long)]
        clean: bool,
        #[arg(long)]
        debug: bool,
    },
    /// Test the Accless C++ library
    Test {
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ApplicationsCommand {
    /// Build the Accless applications
    Build {
        /// Force a clean build.
        #[arg(long)]
        clean: bool,
        /// Force a debug build.
        #[arg(long)]
        debug: bool,
        /// Path to the attestation service's public certificate PEM file.
        #[arg(long)]
        as_cert_dir: Option<PathBuf>,
        /// Whether to build the application inside a cVM.
        #[arg(long, default_value_t = false)]
        in_cvm: bool,
    },
    /// Run one of the Accless applications
    Run {
        /// Type of the application to run
        app_type: applications::ApplicationType,
        /// Name of the application to run
        app_name: applications::ApplicationName,
        /// Application backend.
        #[arg(long)]
        backend: Option<applications::ApplicationBackend>,
        /// Run the application with sudo privileges.
        #[arg(long, default_value_t = false)]
        run_as_root: bool,
        /// Extra flags to pass to the docker run command.
        #[arg(long)]
        extra_docker_flags: Option<Vec<String>>,
        /// Arbitrary arguments to pass to the function.
        #[arg(last = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize the logger.
    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    let mut builder = Builder::from_env(env);
    builder.init();

    let cli = Cli::parse();
    match &cli.task {
        Command::Accless { accless_command } => match accless_command {
            AcclessCommand::Build { clean, debug } => {
                Accless::build(*clean, *debug)?;
            }
            AcclessCommand::Test { args } => {
                Accless::test(args)?;
            }
        },
        Command::Applications {
            applications_command,
        } => match applications_command {
            ApplicationsCommand::Build {
                clean,
                debug,
                as_cert_dir,
                in_cvm,
            } => {
                Applications::build(*clean, *debug, as_cert_dir.clone(), false, *in_cvm)?;
            }
            ApplicationsCommand::Run {
                app_type,
                app_name,
                backend,
                run_as_root,
                extra_docker_flags,
                args,
            } => {
                let extra_docker_flags_str: Option<Vec<&str>> = extra_docker_flags
                    .as_ref()
                    .map(|flags| flags.iter().map(AsRef::as_ref).collect());
                let app_backend = if let Some(backend) = backend {
                    backend
                } else {
                    &applications::ApplicationBackend::Docker
                };

                Applications::run(
                    app_type,
                    app_name,
                    app_backend,
                    *run_as_root,
                    extra_docker_flags_str.as_deref(),
                    args.clone(),
                )?;
            }
        },
        Command::Dev { dev_command } => match dev_command {
            DevCommand::BumpVersion {
                major,
                minor,
                patch,
            } => {
                let num_true = [*major, *minor, *patch].iter().filter(|&&x| x).count();
                if num_true != 1 {
                    log::error!("exactly one of --major, --minor, or --patch must be specified");
                    process::exit(1);
                }
                Dev::bump_code_version(*major, *minor, *patch)?;
            }
            DevCommand::FormatCode { check } => {
                Dev::format_code(*check);
            }
            DevCommand::Tag { force } => {
                Dev::tag_code(*force)?;
            }
            DevCommand::Docker { docker_command } => match docker_command {
                DockerCommand::Build { ctr, push, nocache } => {
                    for c in ctr {
                        Docker::build(c, *push, *nocache);
                    }
                }
                DockerCommand::BuildAll { push, nocache } => {
                    for ctr in DockerContainer::iter_variants() {
                        // Do not push the base build image
                        if *ctr == DockerContainer::Experiments {
                            Docker::build(ctr, false, *nocache);
                        } else {
                            Docker::build(ctr, *push, *nocache);
                        }
                    }
                }
                DockerCommand::Cli { net } => {
                    Docker::cli(*net)?;
                }
                DockerCommand::Run {
                    cmd,
                    mount,
                    cwd,
                    env,
                    net,
                    capture_output,
                } => {
                    Docker::run(
                        cmd,
                        *mount,
                        cwd.as_deref(),
                        env,
                        *net,
                        *capture_output,
                        None,
                    )?;
                }
            },
            DevCommand::Cvm { cvm_command } => match cvm_command {
                CvmCommand::Run { cmd, scp_file, cwd } => {
                    let scp_files_option = if scp_file.is_empty() {
                        None
                    } else {
                        Some(scp_file.as_slice())
                    };
                    cvm::run(cmd, scp_files_option, cwd.as_ref())?;
                }
                CvmCommand::Setup { clean, component } => {
                    cvm::build(*clean, *component)?;
                }
                CvmCommand::Cli { cwd } => {
                    cvm::cli(cwd.as_ref())?;
                }
                CvmCommand::Scp { src_path, dst_path } => {
                    cvm::scp(src_path, dst_path)?;
                }
            },
        },
        Command::Experiments {
            experiments_command: exp,
        } => match exp {
            Experiment::ColdStart { eval_sub_command }
            | Experiment::E2eLatency { eval_sub_command }
            | Experiment::E2eLatencyCold { eval_sub_command }
            | Experiment::ScaleUpLatency { eval_sub_command } => match eval_sub_command {
                E2eSubScommand::Run(run_args) => {
                    tasks::experiments::e2e::run(exp, run_args).await?;
                }
                E2eSubScommand::Plot {} => {
                    tasks::experiments::plot::plot(exp)?;
                }
                E2eSubScommand::UploadState { system } => {
                    tasks::experiments::e2e::upload_state(exp, system).await?;
                }
                E2eSubScommand::UploadWasm {} => {
                    tasks::experiments::e2e::upload_wasm(exp)?;
                }
            },
            Experiment::EscrowCost { ubench_sub_command }
            | Experiment::EscrowXput { ubench_sub_command } => match ubench_sub_command {
                UbenchSubCommand::Run(run_args) => {
                    tasks::experiments::ubench::run(exp, run_args).await?;
                }
                UbenchSubCommand::Plot {} => {
                    tasks::experiments::plot::plot(exp)?;
                }
            },
        },
        Command::S3 { s3_command } => match s3_command {
            S3Command::ClearBucket { bucket_name } => {
                S3::clear_bucket(bucket_name).await;
            }
            S3Command::ClearDir {
                bucket_name,
                prefix,
            } => {
                S3::clear_dir(bucket_name, prefix).await;
            }
            S3Command::GetDir {
                bucket_name,
                s3_path,
                host_path,
            } => {
                S3::get_dir(bucket_name, s3_path, host_path).await;
            }
            S3Command::GetKey { bucket_name, key } => {
                let key_contents = S3::get_key(bucket_name, key).await;
                println!("{key_contents}");
            }
            S3Command::GetUrl { system } => {
                let url = S3::get_url(system);
                println!("{url}");
            }
            S3Command::ListBuckets {} => {
                S3::list_buckets().await;
            }
            S3Command::ListKeys {
                bucket_name,
                prefix,
            } => {
                S3::list_keys(bucket_name, &prefix.as_deref()).await;
            }
            S3Command::UploadDir {
                bucket_name,
                host_path,
                s3_path,
            } => {
                S3::upload_dir(bucket_name, host_path, s3_path).await;
            }
            S3Command::UploadKey {
                bucket_name,
                host_path,
                s3_path,
            } => {
                S3::upload_file(bucket_name, host_path, s3_path).await;
            }
        },
        Command::Azure { az_command } => match az_command {
            AzureCommand::Accless { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_guest(experiments::ACCLESS_VM_NAME, "Standard_DC8as_v5")?;
                    Azure::create_snp_guest(
                        experiments::ACCLESS_ATTESTATION_SERVICE_VM_NAME,
                        "Standard_DC2as_v5",
                    )?;
                    Azure::create_aa(experiments::ACCLESS_MAA_NAME)?;

                    Azure::open_vm_ports(experiments::ACCLESS_VM_NAME, &[22])?;
                    Azure::open_vm_ports(
                        experiments::ACCLESS_ATTESTATION_SERVICE_VM_NAME,
                        &[22, 8443],
                    )?;
                }
                AzureSubCommand::Provision {} => {
                    let server_ip =
                        Azure::get_vm_ip(experiments::ACCLESS_ATTESTATION_SERVICE_VM_NAME)?;
                    let accless_code_dir = format!(
                        "/home/{}/{}",
                        azure::AZURE_USERNAME,
                        experiments::ACCLESS_VM_CODE_DIR
                    );
                    let as_cert_dir =
                        format!("{accless_code_dir}/config/attestation-service/certs");

                    let vars: HashMap<&str, &str> = HashMap::from([
                        ("as_ip", server_ip.as_str()),
                        ("accless_code_dir", accless_code_dir.as_str()),
                        ("as_cert_dir", as_cert_dir.as_str()),
                    ]);
                    Azure::provision_with_ansible("accless", "accless", Some(vars))?;
                }
                AzureSubCommand::Ssh {} => {
                    println!("client:");
                    println!("{}", Azure::build_ssh_command("accless-cvm")?);
                    println!("attestation server:");
                    println!("{}", Azure::build_ssh_command("accless-as")?);
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest("accless-cvm")?;
                    Azure::delete_snp_guest("accless-as")?;
                    Azure::delete_aa("accless")?;
                }
            },
            AzureCommand::AttestationService { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_guest(
                        experiments::ATTESTATION_SERVICE_VM_NAME,
                        "Standard_DC8as_v5",
                    )?;
                    Azure::open_vm_ports(experiments::ATTESTATION_SERVICE_VM_NAME, &[22, 8443])?;
                }
                AzureSubCommand::Provision {} => {
                    let service_ip = Azure::get_vm_ip(experiments::ATTESTATION_SERVICE_VM_NAME)?;

                    let vars: HashMap<&str, &str> = HashMap::from([("as_ip", service_ip.as_str())]);
                    Azure::provision_with_ansible(
                        "attestation-service",
                        "attestationservice",
                        Some(vars),
                    )?;
                }
                AzureSubCommand::Ssh {} => {
                    println!(
                        "{}",
                        Azure::build_ssh_command(experiments::ATTESTATION_SERVICE_VM_NAME)?
                    );
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest(experiments::ATTESTATION_SERVICE_VM_NAME)?;
                }
            },
            AzureCommand::ManagedHSM { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_guest(experiments::MHSM_CLIENT_VM_NAME, "Standard_DC8as_v5")?;
                    Azure::create_aa(experiments::MHSM_ATTESTATION_SERVICE_NAME)?;
                    // WARNING: the key release policy in the mHSM depends
                    // on the name of the attestaion provider even though it
                    // is not passed as an argument (it is used in the ARM
                    // template file: ./config/azure/mhsm_skr_policy.json)
                    Azure::create_mhsm(
                        experiments::MHSM_NAME,
                        experiments::MHSM_CLIENT_VM_NAME,
                        experiments::MHSM_KEY,
                    )?;

                    Azure::open_vm_ports(experiments::MHSM_CLIENT_VM_NAME, &[22])?;
                }
                AzureSubCommand::Provision {} => {
                    Azure::provision_with_ansible("accless-mhsm", "mhsm", None)?;
                }
                AzureSubCommand::Ssh {} => {
                    println!(
                        "{}",
                        Azure::build_ssh_command(experiments::MHSM_CLIENT_VM_NAME)?
                    );
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest(experiments::MHSM_CLIENT_VM_NAME)?;
                    Azure::delete_aa(experiments::MHSM_ATTESTATION_SERVICE_NAME)?;
                    Azure::delete_mhsm(experiments::MHSM_NAME)?;
                }
            },
            AzureCommand::SgxFaasm { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_sgx_vm("sgx-faasm-vm", "Standard_DC8ds_v3")?;
                }
                AzureSubCommand::Provision {} => {
                    let version = Env::get_version().unwrap();
                    let faasm_version = Env::get_faasm_version();
                    let vars: HashMap<&str, &str> = HashMap::from([
                        ("accless_version", version.as_str()),
                        ("faasm_version", faasm_version.as_str()),
                    ]);
                    Azure::provision_with_ansible("sgx-faasm", "sgxfaasm", Some(vars))?;
                }
                AzureSubCommand::Ssh {} => {
                    println!("{}", Azure::build_ssh_command("sgx-faasm-vm")?);
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_sgx_vm("sgx-faasm-vm")?;
                }
            },
            AzureCommand::SnpKnative { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_cc_vm("snp-knative-vm", "Standard_DC8as_cc_v5")?;
                }
                AzureSubCommand::Provision {} => {
                    let version = Env::get_version().unwrap();
                    let vars: HashMap<&str, &str> =
                        HashMap::from([("accless_version", version.as_str())]);
                    Azure::provision_with_ansible("snp-knative", "snpknative", Some(vars))?;
                }
                AzureSubCommand::Ssh {} => {
                    println!("{}", Azure::build_ssh_command("snp-knative-vm")?);
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_sgx_vm("snp-knative-vm")?;
                }
            },
            AzureCommand::Trustee { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_guest(
                        experiments::TRUSTEE_CLIENT_VM_NAME,
                        "Standard_DC8as_v5",
                    )?;
                    Azure::create_snp_guest(
                        experiments::TRUSTEE_SERVER_VM_NAME,
                        "Standard_DC2as_v5",
                    )?;

                    // Open port 8080 on the server VM
                    Azure::open_vm_ports(experiments::TRUSTEE_CLIENT_VM_NAME, &[22])?;
                    Azure::open_vm_ports(experiments::TRUSTEE_SERVER_VM_NAME, &[22, 8080])?;
                }
                AzureSubCommand::Provision {} => {
                    let server_ip = Azure::get_vm_ip(experiments::TRUSTEE_SERVER_VM_NAME)?;
                    let trustee_code_dir = format!(
                        "/home/{}/git/confidential-containers/trustee",
                        azure::AZURE_USERNAME
                    );
                    let accless_code_dir =
                        format!("/home/{}/git/faasm/accless", azure::AZURE_USERNAME);

                    let vars: HashMap<&str, &str> = HashMap::from([
                        ("kbs_ip", server_ip.as_str()),
                        ("trustee_code_dir", trustee_code_dir.as_str()),
                        ("accless_code_dir", accless_code_dir.as_str()),
                    ]);
                    Azure::provision_with_ansible("accless-trustee", "trustee", Some(vars))?;
                }
                AzureSubCommand::Ssh {} => {
                    println!("client:");
                    println!(
                        "{}",
                        Azure::build_ssh_command(experiments::TRUSTEE_CLIENT_VM_NAME)?
                    );
                    println!("server:");
                    println!(
                        "{}",
                        Azure::build_ssh_command(experiments::TRUSTEE_SERVER_VM_NAME)?
                    );
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest(experiments::TRUSTEE_CLIENT_VM_NAME)?;
                    Azure::delete_snp_guest(experiments::TRUSTEE_SERVER_VM_NAME)?;
                }
            },
            AzureCommand::Utils { az_utils_command } => match az_utils_command {
                AzureUtilsCommand::InAzureVm {} => {
                    if Azure::is_azure_vm().await {
                        info!("main(): executing inside azure VM");
                    } else {
                        info!("main(): NOT executing inside azure VM");
                    }
                }
            },
        },
        Command::AttestationService {
            attestation_service_command,
        } => match attestation_service_command {
            AttestationServiceCommand::Build {} => {
                AttestationService::build()?;
            }
            AttestationServiceCommand::Run {
                certs_dir,
                port,
                sgx_pccs_url,
                force_clean_certs,
                mock,
                rebuild,
                background,
                overwrite_external_ip,
            } => {
                AttestationService::run(
                    certs_dir.as_deref(),
                    *port,
                    sgx_pccs_url.as_deref(),
                    *force_clean_certs,
                    *mock,
                    *rebuild,
                    *background,
                    overwrite_external_ip.clone(),
                )?;
            }
            AttestationServiceCommand::Stop {} => {
                AttestationService::stop()?;
            }
            AttestationServiceCommand::Health { url, cert_dir } => {
                AttestationService::health(url.clone(), cert_dir.clone()).await?;
            }
        },
    }

    Ok(())
}

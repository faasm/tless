use crate::{
    env::Env,
    tasks::{
        azure::Azure,
        dag::Dag,
        dev::Dev,
        docker::{Docker, DockerContainer},
        eval::{Eval, EvalExperiment, EvalRunArgs},
        s3::S3,
        ubench::{MicroBenchmarks, Ubench, UbenchRunArgs},
    },
};
use clap::{Parser, Subcommand};
use std::{collections::HashMap, process};

pub mod attestation_service;
pub mod env;
pub mod tasks;

#[derive(Parser)]
struct Cli {
    // The name of the task to execute
    #[clap(subcommand)]
    task: Command,

    #[arg(short, long, global = true)]
    debug: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Register and manage workflows expressed as DAGs
    Dag {
        #[command(subcommand)]
        dag_command: DagCommand,
    },
    /// Development-related tasks
    Dev {
        #[command(subcommand)]
        dev_command: DevCommand,
    },
    /// Build and push different docker images
    Docker {
        #[command(subcommand)]
        docker_command: DockerCommand,
    },
    /// Run evaluation experiments and plot results
    Eval {
        #[command(subcommand)]
        eval_command: EvalCommand,
    },
    /// Run microbenchmark
    Ubench {
        #[command(subcommand)]
        ubench_command: UbenchCommand,
    },
    /// Interact with an S3 (MinIO server)
    S3 {
        #[command(subcommand)]
        s3_command: S3Command,
    },
    /// Provision SGX or SNP capable VMs on Azure
    Azure {
        #[command(subcommand)]
        az_command: AzureCommand,
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
}

#[derive(Debug, Subcommand)]
enum DockerCommand {
    /// Build one of Accless' docker containers. Run build --help to see the
    /// possibe options
    Build {
        #[arg(short, long, num_args = 1.., value_name = "CTR_NAME")]
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
        /// Command to run inside the container
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
    },
}

#[derive(Debug, Subcommand)]
enum EvalSubCommand {
    /// Run
    Run(EvalRunArgs),
    /// Plot
    Plot {},
    UploadState {
        /// Whereas we are using S3 with 'faasm' or 'knative'
        system: String,
    },
    UploadWasm {},
}

#[derive(Debug, Subcommand)]
enum EvalCommand {
    /// Measure the CDF of cold-starts with or w/out our access control
    ColdStart {
        #[command(subcommand)]
        eval_sub_command: EvalSubCommand,
    },
    /// Evaluate end-to-end execution latency for different workflows
    E2eLatency {
        #[command(subcommand)]
        eval_sub_command: EvalSubCommand,
    },
    /// Evaluate end-to-end execution latency (cold) for different workflows
    E2eLatencyCold {
        #[command(subcommand)]
        eval_sub_command: EvalSubCommand,
    },
    /// Evaluate the latency when scaling-up the number of functions in the
    /// workflow
    ScaleUpLatency {
        #[command(subcommand)]
        eval_sub_command: EvalSubCommand,
    },
}

#[derive(Debug, Subcommand)]
enum UbenchCommand {
    /// Measure the cost per user of different configurations
    EscrowCost {
        #[command(subcommand)]
        ubench_sub_command: UbenchSubCommand,
    },
    /// Measure the throughput of the trusted escrow as we increase the number
    /// of parallel authorization requests
    EscrowXput {
        #[command(subcommand)]
        ubench_sub_command: UbenchSubCommand,
    },
}

#[derive(Debug, Subcommand)]
enum UbenchSubCommand {
    /// Run
    Run(UbenchRunArgs),
    /// Plot
    Plot {},
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
}

#[derive(Debug, Subcommand)]
enum AzureSubCommand {
    /// Create an Azure resource
    Create {},
    /// Provision Azure resource using Ansible
    Provision {},
    /// Copy the results directory corresponding to this resoiurce
    ScpResults {},
    /// Get a SSH command into the Azure resource (if applicable)
    Ssh {},
    /// Delete the Azure resource
    Delete {},
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize the logger based on the debug flag
    if cli.debug {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    match &cli.task {
        Command::Dag { dag_command } => match dag_command {
            DagCommand::Upload { name, yaml_path } => {
                Dag::upload(name, yaml_path).await?;
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
        },
        Command::Docker { docker_command } => match docker_command {
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
                Docker::cli(*net);
            }
            DockerCommand::Run {
                cmd,
                mount,
                cwd,
                env,
                net,
            } => {
                Docker::run(cmd, *mount, cwd.as_deref(), env, *net);
            }
        },
        Command::Eval { eval_command } => match eval_command {
            EvalCommand::ColdStart { eval_sub_command } => match eval_sub_command {
                EvalSubCommand::Run(run_args) => {
                    Eval::run(&EvalExperiment::ColdStart, run_args).await?;
                }
                EvalSubCommand::Plot {} => {
                    Eval::plot(&EvalExperiment::ColdStart)?;
                }
                EvalSubCommand::UploadState { system } => {
                    Eval::upload_state(&EvalExperiment::ColdStart, system).await?;
                }
                EvalSubCommand::UploadWasm {} => {
                    Eval::upload_wasm(&EvalExperiment::ColdStart)?;
                }
            },
            EvalCommand::E2eLatency { eval_sub_command } => match eval_sub_command {
                EvalSubCommand::Run(run_args) => {
                    Eval::run(&EvalExperiment::E2eLatency, run_args).await?;
                }
                EvalSubCommand::Plot {} => {
                    Eval::plot(&EvalExperiment::E2eLatency)?;
                }
                EvalSubCommand::UploadState { system } => {
                    Eval::upload_state(&EvalExperiment::E2eLatency, system).await?;
                }
                EvalSubCommand::UploadWasm {} => {
                    Eval::upload_wasm(&EvalExperiment::E2eLatency)?;
                }
            },
            EvalCommand::E2eLatencyCold { eval_sub_command } => match eval_sub_command {
                EvalSubCommand::Run(run_args) => {
                    Eval::run(&EvalExperiment::E2eLatencyCold, run_args).await?;
                }
                EvalSubCommand::Plot {} => {
                    Eval::plot(&EvalExperiment::E2eLatencyCold)?;
                }
                EvalSubCommand::UploadState { system } => {
                    Eval::upload_state(&EvalExperiment::E2eLatencyCold, system).await?;
                }
                EvalSubCommand::UploadWasm {} => {
                    Eval::upload_wasm(&EvalExperiment::E2eLatencyCold)?;
                }
            },
            EvalCommand::ScaleUpLatency { eval_sub_command } => match eval_sub_command {
                EvalSubCommand::Run(run_args) => {
                    Eval::run(&EvalExperiment::ScaleUpLatency, run_args).await?;
                }
                EvalSubCommand::Plot {} => {
                    Eval::plot(&EvalExperiment::ScaleUpLatency)?;
                }
                EvalSubCommand::UploadState { system } => {
                    Eval::upload_state(&EvalExperiment::ScaleUpLatency, system).await?;
                }
                EvalSubCommand::UploadWasm {} => {
                    Eval::upload_wasm(&EvalExperiment::ScaleUpLatency)?;
                }
            },
        },
        Command::Ubench { ubench_command } => match ubench_command {
            UbenchCommand::EscrowCost { ubench_sub_command } => match ubench_sub_command {
                UbenchSubCommand::Run(run_args) => {
                    Ubench::run(&MicroBenchmarks::EscrowCost, run_args).await;
                }
                UbenchSubCommand::Plot {} => {
                    Ubench::plot(&MicroBenchmarks::EscrowCost);
                }
            },
            UbenchCommand::EscrowXput { ubench_sub_command } => match ubench_sub_command {
                UbenchSubCommand::Run(run_args) => {
                    Ubench::run(&MicroBenchmarks::EscrowXput, run_args).await;
                }
                UbenchSubCommand::Plot {} => {
                    Ubench::plot(&MicroBenchmarks::EscrowXput);
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
                    Azure::create_snp_guest("accless-cvm", "Standard_DC8as_v5");
                    Azure::create_snp_guest("accless-as", "Standard_DC2as_v5");
                    Azure::create_aa("accless");

                    Azure::open_vm_ports("accless-cvm", &[22]);
                    Azure::open_vm_ports("accless-as", &[22, 8443]);
                }
                AzureSubCommand::Provision {} => {
                    let client_ip = Azure::get_vm_ip("accless-cvm");
                    let server_ip = Azure::get_vm_ip("accless-as");

                    let vars: HashMap<&str, &str> = HashMap::from([("as_ip", server_ip.as_str())]);
                    Azure::provision_with_ansible("accless", "accless", Some(vars));

                    // Copy the necessary stuff from the server to the client
                    let work_dir = "/home/tless/git/faasm/tless/attestation-service/certs/";

                    #[allow(clippy::single_element_loop)]
                    for file in ["cert.pem"] {
                        let scp_cmd_in =
                            format!("scp tless@{server_ip}:{work_dir}/{file} /tmp/{file}");
                        let status = process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd_in)
                            .status()
                            .expect("accli: error scp-ing data (in)");
                        if !status.success() {
                            panic!("accli: error scp-ing data (in)");
                        }

                        let scp_cmd_out =
                            format!("scp /tmp/{file} tless@{client_ip}:{work_dir}/{file}");
                        let status = process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd_out)
                            .status()
                            .expect("accli: error scp-ing data (out)");
                        if !status.success() {
                            panic!("accli: error scp-ing data (out)");
                        }
                    }
                }
                AzureSubCommand::ScpResults {} => {
                    let src_results_dir = "/home/tless/git/faasm/tless/ubench/escrow-xput/build";
                    let results_file = vec!["accless.csv", "accless-maa.csv"];
                    let result_path = "eval/escrow-xput/data/";

                    for result_file in results_file {
                        let scp_cmd = format!(
                            "{}:{src_results_dir}/{result_file} {}/{result_file}",
                            Azure::build_scp_command("accless-cvm"),
                            Env::proj_root().join(result_path).display(),
                        );

                        process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd)
                            .status()
                            .expect("accli: error scp-ing results");
                    }
                }
                AzureSubCommand::Ssh {} => {
                    println!("client:");
                    Azure::build_ssh_command("accless-cvm");
                    println!("attestation server:");
                    Azure::build_ssh_command("accless-as");
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest("accless-cvm");
                    Azure::delete_snp_guest("accless-as");
                    Azure::delete_aa("accless");
                }
            },
            AzureCommand::AttestationService { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_guest("attestation-service", "Standard_DC8as_v5");
                    Azure::open_vm_ports("attestation-service", &[22, 8443]);
                }
                AzureSubCommand::Provision {} => {
                    let service_ip = Azure::get_vm_ip("attestation-service");

                    let vars: HashMap<&str, &str> = HashMap::from([("as_ip", service_ip.as_str())]);
                    Azure::provision_with_ansible(
                        "attestation-service",
                        "attestationservice",
                        Some(vars),
                    );
                }
                AzureSubCommand::ScpResults {} => {
                    println!("scp-results does not apply");
                }
                AzureSubCommand::Ssh {} => {
                    Azure::build_ssh_command("attestation-service");
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest("attestation-service");
                }
            },
            AzureCommand::ManagedHSM { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_guest("tless-mhsm-cvm", "Standard_DC8as_v5");
                    Azure::create_aa("tlessmhsm");
                    // WARNING: the key release policy in the mHSM depends
                    // on the name of the attestaion provider even though it
                    // is not passed as an argument (it is used in the ARM
                    // template file: ./azure/mhsm_skr_policy.json)
                    Azure::create_mhsm("tless-mhsm-kv", "tless-mhsm-cvm", "tless-mhsm-key");

                    Azure::open_vm_ports("tless-mhsm-cvm", &[22]);
                }
                AzureSubCommand::Provision {} => {
                    Azure::provision_with_ansible("tless-mhsm", "mhsm", None);
                }
                AzureSubCommand::ScpResults {} => {
                    let src_results_dir = "/home/tless/git/faasm/tless";
                    let result_path = "eval/escrow-xput/data/managed-hsm.csv";

                    let scp_cmd = format!(
                        "{}:{src_results_dir}/{result_path} {}",
                        Azure::build_scp_command("tless-mhsm-cvm"),
                        Env::proj_root().join(result_path).display(),
                    );

                    process::Command::new("sh")
                        .arg("-c")
                        .arg(scp_cmd)
                        .status()
                        .expect("accli: error scp-ing results");
                }
                AzureSubCommand::Ssh {} => {
                    Azure::build_ssh_command("tless-mhsm-cvm");
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest("tless-mhsm-cvm");
                    Azure::delete_aa("tlessmhsm");
                    Azure::delete_mhsm("tless-mhsm-kv");
                }
            },
            AzureCommand::SgxFaasm { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_sgx_vm("sgx-faasm-vm", "Standard_DC8ds_v3");
                }
                AzureSubCommand::Provision {} => {
                    let version = Env::get_version().unwrap();
                    let faasm_version = Env::get_faasm_version();
                    let vars: HashMap<&str, &str> = HashMap::from([
                        ("accless_version", version.as_str()),
                        ("faasm_version", faasm_version.as_str()),
                    ]);
                    Azure::provision_with_ansible("sgx-faasm", "sgxfaasm", Some(vars));
                }
                AzureSubCommand::ScpResults {} => {
                    // let src_results_dir = "/home/tless/git/faasm/tless/eval/cold-start/data";
                    let src_results_dir = "/home/tless/git/faasm/tless/eval/scale-up-latency/data";
                    // let results_file = vec!["faasm.csv", "sgx-faasm.csv", "accless-faasm.csv"];
                    let results_file = vec!["accless-faasm.csv"];
                    let result_path = "eval/scale-up-latency/data";

                    for result_file in results_file {
                        let scp_cmd = format!(
                            "{}:{src_results_dir}/{result_file} {}/{result_file}",
                            Azure::build_scp_command("sgx-faasm-vm"),
                            Env::proj_root().join(result_path).display(),
                        );

                        process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd)
                            .status()
                            .expect("accli: error scp-ing results");
                    }
                }
                AzureSubCommand::Ssh {} => {
                    Azure::build_ssh_command("sgx-faasm-vm");
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_sgx_vm("sgx-faasm-vm");
                }
            },
            AzureCommand::SnpKnative { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_cc_vm("snp-knative-vm", "Standard_DC8as_cc_v5");
                }
                AzureSubCommand::Provision {} => {
                    let version = Env::get_version().unwrap();
                    let vars: HashMap<&str, &str> =
                        HashMap::from([("accless_version", version.as_str())]);
                    Azure::provision_with_ansible("snp-knative", "snpknative", Some(vars));
                }
                AzureSubCommand::ScpResults {} => {
                    let src_results_dir = "/home/tless/git/faasm/tless/eval/cold-start/data";
                    let results_file =
                        vec!["knative.csv", "snp-knative.csv", "accless-knative.csv"];
                    let result_path = "eval/cold-start/data";

                    for result_file in results_file {
                        let scp_cmd = format!(
                            "{}:{src_results_dir}/{result_file} {}/{result_file}",
                            Azure::build_scp_command("snp-knative-vm"),
                            Env::proj_root().join(result_path).display(),
                        );

                        process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd)
                            .status()
                            .expect("accli: error scp-ing results");
                    }
                }
                AzureSubCommand::Ssh {} => {
                    Azure::build_ssh_command("snp-knative-vm");
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_sgx_vm("snp-knative-vm");
                }
            },
            AzureCommand::Trustee { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    // DC2 is 62.78$/month -> original experiments w/ this
                    // DC4 is DC2 * 2
                    // DC8 is DC2 * 4
                    Azure::create_snp_guest("tless-trustee-client", "Standard_DC2as_v5");
                    Azure::create_snp_guest("tless-trustee-server", "Standard_DC2as_v5");

                    // Open port 8080 on the server VM
                    Azure::open_vm_ports("tless-trustee-client", &[22]);
                    Azure::open_vm_ports("tless-trustee-server", &[22, 8080]);
                }
                AzureSubCommand::Provision {} => {
                    let client_ip = Azure::get_vm_ip("tless-trustee-client");
                    let server_ip = Azure::get_vm_ip("tless-trustee-server");

                    let vars: HashMap<&str, &str> = HashMap::from([("kbs_ip", server_ip.as_str())]);
                    Azure::provision_with_ansible("tless-trustee", "trustee", Some(vars));

                    // Copy the necessary stuff from the server to the client
                    let work_dir = "/home/tless/git/confidential-containers/trustee/kbs/test/work";
                    for file in ["https.crt", "kbs.key", "tee.key"] {
                        let scp_cmd_in =
                            format!("scp tless@{server_ip}:{work_dir}/{file} /tmp/{file}");
                        let status = process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd_in)
                            .status()
                            .expect("accli: error scp-ing data (in)");
                        if !status.success() {
                            panic!("accli: error scp-ing data (in)");
                        }

                        let scp_cmd_out =
                            format!("scp /tmp/{file} tless@{client_ip}:{work_dir}/{file}");
                        let status = process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd_out)
                            .status()
                            .expect("accli: error scp-ing data (out)");
                        if !status.success() {
                            panic!("accli: error scp-ing data (out)");
                        }
                    }
                }
                AzureSubCommand::ScpResults {} => {
                    let src_results_dir = "/home/tless/git/faasm/tless";
                    let result_path = "eval/escrow-xput/data/trustee.csv";

                    let scp_cmd = format!(
                        "{}:{src_results_dir}/{result_path} {}",
                        Azure::build_scp_command("tless-trustee-client"),
                        Env::proj_root().join(result_path).display(),
                    );

                    process::Command::new("sh")
                        .arg("-c")
                        .arg(scp_cmd)
                        .status()
                        .expect("accli: error scp-ing results");
                }
                AzureSubCommand::Ssh {} => {
                    println!("client:");
                    Azure::build_ssh_command("tless-trustee-client");
                    println!("server:");
                    Azure::build_ssh_command("tless-trustee-server");
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest("tless-trustee-client");
                    Azure::delete_snp_guest("tless-trustee-server");
                }
            },
        },
    }

    Ok(())
}

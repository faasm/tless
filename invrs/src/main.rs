use crate::env::Env;
use crate::tasks::azure::Azure;
use crate::tasks::dag::Dag;
use crate::tasks::docker::{Docker, DockerContainer};
use crate::tasks::eval::{Eval, EvalExperiment, EvalRunArgs};
use crate::tasks::s3::S3;
use crate::tasks::ubench::{MicroBenchmarks, Ubench, UbenchRunArgs};
use clap::{Parser, Subcommand};
use env_logger;
use std::process;

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
enum DockerCommand {
    Build {
        #[arg(short, long, num_args = 1.., value_name = "CTR_NAME")]
        ctr: Vec<DockerContainer>,
        #[arg(long)]
        push: bool,
        #[arg(long)]
        nocache: bool,
    },
    BuildAll {
        #[arg(long)]
        push: bool,
        #[arg(long)]
        nocache: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EvalSubCommand {
    /// Run
    Run(EvalRunArgs),
    /// Plot
    Plot {},
}

#[derive(Debug, Subcommand)]
enum EvalCommand {
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
    /// Measure the throughput of the trusted escrow as we increase the number
    /// of parallel authorization requests
    EscrowXput {
        #[command(subcommand)]
        ubench_sub_command: UbenchSubCommand,
    },
    /// Microbenchmark to measure the time to verify an eDAG
    VerifyEdag {
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
    /// Deploy an environment with an SNP cVM and a managed HSM acting as
    /// relying party to perform secure key release (SKR)
    ManagedHSM {
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
async fn main() {
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
                Dag::upload(name, yaml_path).await;
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
        },
        Command::Eval { eval_command } => match eval_command {
            EvalCommand::E2eLatency { eval_sub_command } => match eval_sub_command {
                EvalSubCommand::Run(run_args) => {
                    Eval::run(&EvalExperiment::E2eLatency, run_args).await;
                }
                EvalSubCommand::Plot {} => {
                    Eval::plot(&EvalExperiment::E2eLatency);
                }
            },
            EvalCommand::E2eLatencyCold { eval_sub_command } => match eval_sub_command {
                EvalSubCommand::Run(run_args) => {
                    Eval::run(&EvalExperiment::E2eLatencyCold, run_args).await;
                }
                EvalSubCommand::Plot {} => {
                    Eval::plot(&EvalExperiment::E2eLatencyCold);
                }
            },
            EvalCommand::ScaleUpLatency { eval_sub_command } => match eval_sub_command {
                EvalSubCommand::Run(run_args) => {
                    Eval::run(&EvalExperiment::ScaleUpLatency, run_args).await;
                }
                EvalSubCommand::Plot {} => {
                    Eval::plot(&EvalExperiment::ScaleUpLatency);
                }
            },
        },
        Command::Ubench { ubench_command } => match ubench_command {
            UbenchCommand::EscrowXput { ubench_sub_command } => match ubench_sub_command {
                UbenchSubCommand::Run(run_args) => {
                    Ubench::run(&MicroBenchmarks::EscrowXput, run_args).await;
                }
                UbenchSubCommand::Plot {} => {
                    Ubench::plot(&MicroBenchmarks::EscrowXput);
                }
            },
            UbenchCommand::VerifyEdag { ubench_sub_command } => match ubench_sub_command {
                UbenchSubCommand::Run(_) => {
                    panic!("verify-edag not supported anymore!");
                }
                UbenchSubCommand::Plot {} => {
                    Ubench::plot(&MicroBenchmarks::VerifyEDag);
                }
            },
        },
        // FIXME: move all S3 methods to &str
        Command::S3 { s3_command } => match s3_command {
            S3Command::ClearBucket { bucket_name } => {
                S3::clear_bucket(bucket_name.to_string()).await;
            }
            S3Command::ClearDir {
                bucket_name,
                prefix,
            } => {
                S3::clear_dir(bucket_name.to_string(), prefix.to_string()).await;
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
            S3Command::ListBuckets {} => {
                S3::list_buckets().await;
            }
            S3Command::ListKeys {
                bucket_name,
                prefix,
            } => {
                S3::list_keys(bucket_name.to_string(), prefix).await;
            }
            S3Command::UploadDir {
                bucket_name,
                host_path,
                s3_path,
            } => {
                S3::upload_dir(
                    bucket_name.to_string(),
                    host_path.to_string(),
                    s3_path.to_string(),
                )
                .await;
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
                        .expect("invrs: error scp-ing results");
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
            AzureCommand::Trustee { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    // DC2 is 62.78$/month
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

                    Azure::provision_with_ansible(
                        "tless-trustee",
                        "trustee",
                        Some(format!("kbs_ip={server_ip}").as_str()),
                    );

                    // Copy the necessary stuff from the server to the client
                    let work_dir = "/home/tless/git/confidential-containers/trustee/kbs/test/work";
                    for file in ["https.crt", "kbs.key", "tee.key"] {
                        let scp_cmd_in =
                            format!("scp tless@{server_ip}:{work_dir}/{file} /tmp/{file}");
                        let status = process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd_in)
                            .status()
                            .expect("invrs: error scp-ing data (in)");
                        if !status.success() {
                            panic!("invrs: error scp-ing data (in)");
                        }

                        let scp_cmd_out =
                            format!("scp /tmp/{file} tless@{client_ip}:{work_dir}/{file}");
                        let status = process::Command::new("sh")
                            .arg("-c")
                            .arg(scp_cmd_out)
                            .status()
                            .expect("invrs: error scp-ing data (out)");
                        if !status.success() {
                            panic!("invrs: error scp-ing data (out)");
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
                        .expect("invrs: error scp-ing results");
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
}

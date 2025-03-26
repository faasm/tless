use crate::tasks::azure::Azure;
use crate::tasks::dag::Dag;
use crate::tasks::docker::{Docker, DockerContainer};
use crate::tasks::eval::{Eval, EvalExperiment, EvalRunArgs};
use crate::tasks::s3::S3;
use crate::tasks::ubench::{MicroBenchmarks, Ubench, UbenchRunArgs};
use clap::{Parser, Subcommand};
use env_logger;

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
    /// Measure the throughput of the trusted escrow as we increase the number
    /// of parallel authorization requests
    EscrowXput {
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
    /// Provision a managed SNP cVM in Azure
    SnpGuest {
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
            // TODO:
            EvalCommand::EscrowXput {} => {},
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
            UbenchCommand::VerifyEdag { ubench_sub_command } => match ubench_sub_command {
                UbenchSubCommand::Run(run_args) => {
                    Ubench::run(&MicroBenchmarks::VerifyEDag, run_args);
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
            AzureCommand::SnpGuest { az_sub_command } => match az_sub_command {
                AzureSubCommand::Create {} => {
                    Azure::create_snp_guest();
                }
                AzureSubCommand::Provision {} => {
                    Azure::provision_snp_guest();
                }
                AzureSubCommand::Ssh {} => {
                    Azure::build_ssh_command();
                }
                AzureSubCommand::Delete {} => {
                    Azure::delete_snp_guest();
                }
            },
        },
    }
}

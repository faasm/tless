use crate::tasks::docker::Docker;
use crate::tasks::s3::S3;
use crate::tasks::workflows::Workflows;
use clap::{Parser, Subcommand};

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
    List {},

    Docker {
        #[command(subcommand)]
        docker_command: DockerCommand,
    },

    S3 {
        #[command(subcommand)]
        s3_command: S3Command,
    },

    Workflows {
        function: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum DockerCommand {
    Build {
        #[arg(long)]
        ctr: String,
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
pub enum S3Command {
    /// Clear a given bucket in an S3 server
    ClearBucket {
        #[arg(long)]
        bucket_name: String,
    },
    /// Clear a sub-tree in an S3 bucket indicated by a prefix
    ClearDir {
        #[arg(long)]
        bucket_name: String,
        #[arg(long)]
        prefix: String,
    },
    /// List all buckets in an S3 server
    ListBuckets {},
    /// List all keys in an S3 bucket
    ListKeys {
        /// Name of the bucket
        #[arg(long)]
        bucket_name: String,
    },
    /// Upload a directory to S3
    UploadDir {
        /// Name of the bucket to store files in
        #[arg(long)]
        bucket_name: String,
        /// Host path to upload files from
        #[arg(long)]
        host_path: String,
        /// Path in the S3 server to store files to
        #[arg(long)]
        s3_path: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.task {
        Command::List {} => {}
        Command::Docker { docker_command } => match docker_command {
            DockerCommand::Build { ctr, push, nocache } => {
                Docker::build(ctr.to_string(), *push, *nocache);
            }
            DockerCommand::BuildAll { push, nocache } => {
                let ctrs = vec!["tless-experiments", "tless-knative-worker"];

                for ctr in &ctrs {
                    // Do not push the base build image
                    if *ctr == "tless-experiments" {
                        Docker::build(ctr.to_string(), false, *nocache);
                    } else {
                        Docker::build(ctr.to_string(), *push, *nocache);
                    }
                }
            }
        },
        Command::S3 { s3_command } => match s3_command {
            S3Command::ClearBucket { bucket_name } => {
                S3::clear_bucket(bucket_name.to_string()).await;
            }
            S3Command::ClearDir { bucket_name, prefix } => {
                S3::clear_dir(bucket_name.to_string(), prefix.to_string()).await;
            }
            S3Command::ListBuckets {} => {
                S3::list_buckets().await;
            }
            S3Command::ListKeys { bucket_name } => {
                S3::list_keys(bucket_name.to_string()).await;
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
        },
        Command::Workflows { function } => Workflows::do_cmd(function.to_string()),
    }
}

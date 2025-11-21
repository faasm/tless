use crate::{env::Env, tasks::s3::S3};
use clap::ValueEnum;
use log::debug;
use std::{env, fmt, path::PathBuf, str::FromStr};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ValueEnum)]
pub enum Workflow {
    Finra,
    MlTraining,
    MlInference,
    WordCount,
}

impl fmt::Display for Workflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Workflow::Finra => write!(f, "finra"),
            Workflow::MlTraining => write!(f, "ml-training"),
            Workflow::MlInference => write!(f, "ml-inference"),
            Workflow::WordCount => write!(f, "word-count"),
        }
    }
}

impl FromStr for Workflow {
    type Err = ();

    fn from_str(input: &str) -> Result<Workflow, Self::Err> {
        match input {
            "finra" => Ok(Workflow::Finra),
            "ml-inference" => Ok(Workflow::MlInference),
            "ml-training" => Ok(Workflow::MlTraining),
            "word-count" => Ok(Workflow::WordCount),
            _ => Err(()),
        }
    }
}

impl Workflow {
    pub fn iter_variants() -> std::slice::Iter<'static, Workflow> {
        static VARIANTS: [Workflow; 4] = [
            Workflow::Finra,
            Workflow::MlTraining,
            Workflow::MlInference,
            Workflow::WordCount,
        ];
        VARIANTS.iter()
    }
}

#[derive(Debug)]
pub struct Workflows {}

impl Workflows {
    pub fn get_root() -> PathBuf {
        let mut path = env::current_dir().expect("invrs: failed to get current directory");
        path.push("workflows");
        path
    }

    pub async fn upload_workflow_state(
        workflow: &Workflow,
        bucket_name: &str,
        clean: bool,
        dag_only: bool,
    ) -> anyhow::Result<()> {
        // Note that cleaning here means cleaning the outputs of previous runs
        if clean {
            for key_dir in ["outputs", "cert-chains"] {
                S3::clear_dir(bucket_name, &format!("{workflow}/{key_dir}")).await;
            }
        }

        // First, upload the DAG
        let _yaml_path = Env::proj_root()
            .join("workflows")
            .join(format!("{workflow}"))
            .join("accless.yaml");
        // Dag::upload(format!("{workflow}").as_str(),
        // yaml_path.to_str().unwrap()).await?;

        if dag_only {
            return Ok(());
        }

        // Then, upload the respective state
        match workflow {
            Workflow::Finra => {
                debug!("foo");
                let mut host_path = S3::get_datasets_root();
                host_path.push(format!("{workflow}"));
                host_path.push("yfinance.csv");
                let s3_path = format!("{workflow}/yfinance.csv");
                S3::upload_file(bucket_name, host_path.to_str().unwrap(), &s3_path).await;
                debug!("bar");
            }
            Workflow::MlTraining => {
                // We upload both datasets until we decide which one to use
                for dataset in ["mnist-images-2k", "mnist-images-10k"] {
                    let mut host_path = S3::get_datasets_root();
                    host_path.push(format!("{workflow}"));
                    host_path.push(dataset);
                    S3::upload_dir(
                        bucket_name,
                        &host_path.display().to_string(),
                        &format!("{workflow}/{dataset}"),
                    )
                    .await;
                }
            }
            Workflow::MlInference => {
                for dataset in ["images-inference-1k", "model"] {
                    let mut host_path = S3::get_datasets_root();
                    host_path.push(format!("{workflow}"));
                    host_path.push(dataset);
                    S3::upload_dir(
                        bucket_name,
                        &host_path.display().to_string(),
                        &format!("{workflow}/{dataset}"),
                    )
                    .await;
                }
            }
            Workflow::WordCount => {
                let mut host_path = S3::get_datasets_root();
                host_path.push(format!("{workflow}"));
                host_path.push("fewer-files");
                S3::upload_dir(
                    bucket_name,
                    &host_path.display().to_string(),
                    &format!("{workflow}/few-files"),
                )
                .await;
            }
        };

        Ok(())
    }

    pub async fn upload_state(
        bucket_name: &str,
        clean: bool,
        dag_only: bool,
    ) -> anyhow::Result<()> {
        if clean {
            S3::clear_bucket(bucket_name).await;
        }

        // Upload state for different workflows
        for workflow in Workflow::iter_variants() {
            Self::upload_workflow_state(workflow, bucket_name, clean, dag_only).await?;
        }

        Ok(())
    }

    pub fn get_faasm_cmdline(workflow: &Workflow) -> &str {
        match workflow {
            Workflow::Finra => "finra/yfinance.csv 20",
            // ML Training workflow with SGX on mnist-10k takes ~30'
            // Workflow::MlTraining => "ml-training/mnist-images-10k 4 8",
            Workflow::MlTraining => "ml-training/mnist-images-2k 2 8",
            // ML Inference relies on the model outputed by ML Training
            Workflow::MlInference => "ml-inference/model ml-inference/images-inference-1k 16",
            Workflow::WordCount => "word-count/few-files",
        }
    }
}

use crate::tasks::s3::S3;
use std::path::PathBuf;
use std::str::FromStr;
use std::{env, fmt};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AvailableWorkflow {
    WordCount,
}

impl fmt::Display for AvailableWorkflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AvailableWorkflow::WordCount => write!(f, "word-count"),
        }
    }
}

impl FromStr for AvailableWorkflow {
    type Err = ();

    fn from_str(input: &str) -> Result<AvailableWorkflow, Self::Err> {
        match input {
            "word-count" => Ok(AvailableWorkflow::WordCount),
            _ => Err(()),
        }
    }
}

impl AvailableWorkflow {
    pub fn iter_variants() -> std::slice::Iter<'static, AvailableWorkflow> {
        static VARIANTS: [AvailableWorkflow; 1] = [AvailableWorkflow::WordCount];
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
        workflow: &AvailableWorkflow,
        bucket_name: &str,
        clean: bool,
    ) {
        if clean {
            S3::clear_dir(bucket_name.to_string(), format!("{workflow}").to_string()).await;
        }

        match workflow {
            AvailableWorkflow::WordCount => {
                let mut host_path = S3::get_datasets_root();
                host_path.push(format!("{workflow}"));
                host_path.push("few-files");
                S3::upload_dir(
                    bucket_name.to_string(),
                    host_path.display().to_string(),
                    format!("{workflow}/few-files"),
                )
                .await;
            }
        };
    }

    pub async fn upload_state(bucket_name: &str, clean: bool) {
        if clean {
            S3::clear_bucket(bucket_name.to_string()).await;
        }

        // Upload state for different workflows
        for workflow in AvailableWorkflow::iter_variants() {
            Self::upload_workflow_state(&workflow, bucket_name, clean).await;
        }
    }

    pub fn get_faasm_cmdline(workflow: &AvailableWorkflow) -> &str {
        match workflow {
            AvailableWorkflow::WordCount => "word-count/few-files",
        }
    }
}

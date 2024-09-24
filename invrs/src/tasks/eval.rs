use clap::{Args, ValueEnum};
use crate::tasks::s3::S3;
use crate::tasks::workflows::{AvailableWorkflow, Workflows};
use std::{env, fmt, fs, io::Write, thread, time};
use std::path::PathBuf;
use std::process::Command;

static EVAL_BUCKET_NAME : &str = "tless";

#[derive(Clone, Debug, ValueEnum)]
pub enum EvalBaseline {
    Faasm,
    SgxFaasm,
    TlessFaasm,
    Knative,
    CcKnative,
    TlessKnative,
}

impl fmt::Display for EvalBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalBaseline::Faasm => write!(f, "faasm"),
            EvalBaseline::SgxFaasm => write!(f, "sgx-faasm"),
            EvalBaseline::TlessFaasm => write!(f, "tless-faasm"),
            EvalBaseline::Knative => write!(f, "knative"),
            EvalBaseline::CcKnative => write!(f, "cc-knative"),
            EvalBaseline::TlessKnative => write!(f, "tless-knative"),
        }
    }
}

pub enum EvalExperiment {
    E2eLatency,
}

impl fmt::Display for EvalExperiment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalExperiment::E2eLatency => write!(f, "e2e-latency"),
        }
    }
}

#[derive(Debug, Args)]
pub struct EvalRunArgs {
    #[arg(long)]
    baseline: EvalBaseline,
    #[arg(long, default_value="10")]
    num_repeats: u32,
    #[arg(long, default_value="1")]
    num_warmup_repeats: u32,
}

#[derive(Debug)]
pub struct Eval {}

impl Eval {
    fn get_root() -> PathBuf {
        let mut path = env::current_dir().expect("invrs: failed to get current directory");
        path.push("eval");
        path
    }

    fn init_data_file(workflow : &AvailableWorkflow, exp : &EvalExperiment, baseline : &EvalBaseline) {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("{}/{exp}/{baseline}_{workflow}.csv", Self::get_root().display()))
            .expect("invrs(eval): failed to write to file");

        match exp {
            EvalExperiment::E2eLatency => {
                writeln!(file, "Run,TimeMs").expect("invrs(eval): failed to write to file");
            }
        }
    }

    fn get_kubectl_cmd() -> String {
        // For the moment, we literally run the `kubectl` command installed
        // as part of `coco-serverless`. We may change this in the future
        match env::var("COCO_SOURCE") {
            Ok(value) => format!("{value}/bin/kubectl"),
            Err(_) => panic!("invrs(eval): failed to read COCO_SOURCE env. var"),
        }
    }

    fn run_kubectl_cmd(cmd: &str) -> String {
        let args: Vec<&str> = cmd.split_whitespace().collect();

        let output = Command::new(Self::get_kubectl_cmd())
            .args(&args[0..])
            .output()
            .expect("invrs(eval): failed to execute kubectl command");

        String::from_utf8(output.stdout).expect("invrs(eval): failed to convert kube command output to string")
    }

    fn wait_for_pods(namespace: &str, label: &str, num_expected: usize) {
        loop {
            thread::sleep(time::Duration::from_secs(2));

            let output = Self::run_kubectl_cmd(&format!("-n {namespace} get pods -l {label} -o jsonpath='{{..status.conditions[?(@.type==\"Ready\")].status}}'"));
            let values: Vec<&str> = output.split_whitespace().collect();

            if values.len() != num_expected {
                println!("Waiting for pods to be ready...");
                continue;
            }

            if !values.iter().all(|&item| item == "'True'") {
                println!("Waiting for pods to be ready...");
                continue;
            }

            break;
        }
    }

    fn wait_for_pod(namespace: &str, label: &str) {
        Self::wait_for_pods(namespace, label, 1);
    }

    fn deploy_workflow(workflow : &AvailableWorkflow) {
        // Common deploy mechanism
        let mut workflow_yaml = Workflows::get_root();
        workflow_yaml.push(format!("{workflow}"));
        workflow_yaml.push("knative");
        workflow_yaml.push("workflow.yaml");
        Self::run_kubectl_cmd(&format!("apply -f {}", workflow_yaml.display()));

        // Specific per-workflow wait command
        match workflow {
            AvailableWorkflow::WordCount => {
                Self::wait_for_pod("tless", "tless.workflows/name=word-count-splitter");
                Self::wait_for_pod("tless", "tless.workflows/name=word-count-reducer");
            }
        }
    }

    /// Run workflow once, and return result depending on the experiment
    async fn run_workflow_once(workflow : &AvailableWorkflow, exp: &EvalExperiment) {
        // Common trigger mechanism
        let mut workflow_yaml = Workflows::get_root();
        workflow_yaml.push(format!("{workflow}"));
        workflow_yaml.push("knative");
        workflow_yaml.push("workflow.yaml");
        Self::run_kubectl_cmd(&format!("apply -f {}", workflow_yaml.display()));

        // Specific per-workflow completion detection
        match workflow {
            AvailableWorkflow::WordCount => {
                // S3::wait_for_key();
            }
        }

        // Specific per-workflow clean-up
        match workflow {
            AvailableWorkflow::WordCount => {
                S3::clear_dir(EVAL_BUCKET_NAME.to_string(), "word-count/few-files/mapper-results/".to_string()).await;
            }
        }
    }

    async fn run_knative_experiment(exp: EvalExperiment, args: &EvalRunArgs) {
        // First, deploy the common services
        let mut k8s_path = Workflows::get_root();
        k8s_path.push("k8s_common.yaml");
        Self::run_kubectl_cmd(&format!("apply -f {}", k8s_path.display()));

        // Wait for the MinIO pod to be ready
        Self::wait_for_pod("tless", "tless.workflows/name=minio");

        // Get the MinIO URL
        let minio_url = Self::run_kubectl_cmd("-n tless get services -o jsonpath={.items[?(@.metadata.name==\"minio\")].spec.clusterIP}");

        // FIXME: consdier doing differently
        unsafe {
            env::set_var("MINIO_URL", minio_url);
        }

        // Upload the state for all workflows
        Workflows::upload_state(EVAL_BUCKET_NAME, true).await;

        // Execute each workload individually
        for workflow in AvailableWorkflow::iter_variants() {
            // Initialise result file
            Self::init_data_file(workflow, &exp, &args.baseline);

            // Deploy workflow
            Self::deploy_workflow(workflow);

            // Do warm-up rounds
            for _ in 0..args.num_warmup_repeats {
                Self::run_workflow_once(workflow, &exp).await;
            }

            // Do actual experiment
            for i in 0..args.num_repeats {
                // let result = Self::run_workflow_once(workflow, exp);
                // write_result_to_file(workflow, &exp, &args.baseline)
            }

            // Delete workflow
            // TODO
            // Self::delete_workflow(workflow);
        }
    }

    pub async fn run(exp: EvalExperiment, args: &EvalRunArgs) {
        match args.baseline {
            EvalBaseline::Knative | EvalBaseline::CcKnative | EvalBaseline::TlessKnative => {
                Self::run_knative_experiment(exp, args).await;
            },
            _ => panic!("invrs(eval): unimplemented baseline: {}", args.baseline),
        }
    }

    pub fn plot(_exp: EvalExperiment) {}
}

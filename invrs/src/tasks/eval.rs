use crate::env::Env;
use crate::tasks::color::{get_color_from_label, FONT_SIZE};
use crate::tasks::docker::{Docker, DockerContainer};
use crate::tasks::s3::S3;
use crate::tasks::workflows::{AvailableWorkflow, Workflows};
use chrono::{DateTime, Duration, TimeZone, Utc};
use clap::{Args, ValueEnum};
use csv::ReaderBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error};
use plotters::prelude::*;
use serde::Deserialize;
use shell_words;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::{collections::BTreeMap, env, fmt, fs, io::Write, str, thread, time};

static EVAL_BUCKET_NAME: &str = "tless";

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvalBaseline {
    Faasm,
    SgxFaasm,
    AcclessFaasm,
    Knative,
    SnpKnative,
    AcclessKnative,
}

impl fmt::Display for EvalBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalBaseline::Faasm => write!(f, "faasm"),
            EvalBaseline::SgxFaasm => write!(f, "sgx-faasm"),
            EvalBaseline::AcclessFaasm => write!(f, "accless-faasm"),
            EvalBaseline::Knative => write!(f, "knative"),
            EvalBaseline::SnpKnative => write!(f, "snp-knative"),
            EvalBaseline::AcclessKnative => write!(f, "accless-knative"),
        }
    }
}

impl FromStr for EvalBaseline {
    type Err = ();

    fn from_str(input: &str) -> Result<EvalBaseline, Self::Err> {
        match input {
            "faasm" => Ok(EvalBaseline::Faasm),
            "sgx-faasm" => Ok(EvalBaseline::SgxFaasm),
            "accless-faasm" => Ok(EvalBaseline::AcclessFaasm),
            "knative" => Ok(EvalBaseline::Knative),
            "snp-knative" => Ok(EvalBaseline::SnpKnative),
            "accless-knative" => Ok(EvalBaseline::AcclessKnative),
            _ => Err(()),
        }
    }
}

impl EvalBaseline {
    pub fn iter_variants() -> std::slice::Iter<'static, EvalBaseline> {
        static VARIANTS: [EvalBaseline; 6] = [
            EvalBaseline::Faasm,
            EvalBaseline::SgxFaasm,
            EvalBaseline::AcclessFaasm,
            EvalBaseline::Knative,
            EvalBaseline::SnpKnative,
            EvalBaseline::AcclessKnative,
        ];
        VARIANTS.iter()
    }

    pub fn get_color(&self) -> RGBColor {
        match self {
            EvalBaseline::Faasm => get_color_from_label("dark-orange"),
            EvalBaseline::SgxFaasm => get_color_from_label("dark-green"),
            EvalBaseline::AcclessFaasm => get_color_from_label("accless"),
            EvalBaseline::Knative => get_color_from_label("dark-blue"),
            EvalBaseline::SnpKnative => get_color_from_label("dark-yellow"),
            EvalBaseline::AcclessKnative => get_color_from_label("accless"),
        }
    }
}

#[derive(PartialEq)]
pub enum EvalExperiment {
    ColdStart,
    E2eLatency,
    E2eLatencyCold,
    ScaleUpLatency,
}

impl fmt::Display for EvalExperiment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalExperiment::ColdStart => write!(f, "cold-start"),
            EvalExperiment::E2eLatency => write!(f, "e2e-latency"),
            EvalExperiment::E2eLatencyCold => write!(f, "e2e-latency-cold"),
            EvalExperiment::ScaleUpLatency => write!(f, "scale-up-latency"),
        }
    }
}

#[derive(Debug, Args)]
pub struct EvalRunArgs {
    #[arg(short, long, num_args = 1.., value_name = "BASELINE")]
    baseline: Vec<EvalBaseline>,
    #[arg(long, default_value = "2")]
    num_repeats: u32,
    #[arg(long, default_value = "1")]
    num_warmup_repeats: u32,
    #[arg(long, default_value = "10")]
    scale_up_range: u32,
}

pub struct ExecutionResult {
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    iter: u32,
}

#[derive(Debug)]
pub struct Eval {}

impl Eval {
    fn get_root() -> PathBuf {
        let mut path = env::current_dir().expect("invrs: failed to get current directory");
        path.push("eval");
        path
    }

    fn get_data_file_name(
        workflow: &AvailableWorkflow,
        exp: &EvalExperiment,
        baseline: &EvalBaseline,
        scale_up_factor: u32,
    ) -> String {
        if *exp == EvalExperiment::ColdStart {
            return format!("{}/{exp}/data/{baseline}.csv", Self::get_root().display());
        }
        if scale_up_factor == 0 {
            format!(
                "{}/{exp}/data/{baseline}_{workflow}.csv",
                Self::get_root().display()
            )
        } else {
            format!(
                "{}/{exp}/data/{baseline}_{workflow}-{scale_up_factor}.csv",
                Self::get_root().display()
            )
        }
    }

    fn init_data_file(
        workflow: &AvailableWorkflow,
        exp: &EvalExperiment,
        baseline: &EvalBaseline,
        scale_up_factor: u32,
    ) {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(Self::get_data_file_name(
                workflow,
                exp,
                baseline,
                scale_up_factor,
            ))
            .expect("invrs(eval): failed to write to file");

        match exp {
            EvalExperiment::ColdStart
            | EvalExperiment::E2eLatency
            | EvalExperiment::E2eLatencyCold
            | EvalExperiment::ScaleUpLatency => {
                writeln!(file, "Run,TimeMs").expect("invrs(eval): failed to write to file");
            }
        }
    }

    fn write_result_to_file(
        workflow: &AvailableWorkflow,
        exp: &EvalExperiment,
        baseline: &EvalBaseline,
        result: &ExecutionResult,
        scale_up_factor: u32,
    ) {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open(Self::get_data_file_name(
                workflow,
                exp,
                baseline,
                scale_up_factor,
            ))
            .expect("invrs(eval): failed to write to file");

        match exp {
            EvalExperiment::ColdStart
            | EvalExperiment::E2eLatency
            | EvalExperiment::E2eLatencyCold
            | EvalExperiment::ScaleUpLatency => {
                let duration: Duration = result.end_time - result.start_time;
                writeln!(file, "{},{}", result.iter, duration.num_milliseconds())
                    .expect("invrs(eval): failed to write to file");
            }
        }
    }

    fn get_all_data_files(exp: &EvalExperiment) -> Vec<PathBuf> {
        // TODO: change to data
        let data_path = format!("{}/{exp}/data", Self::get_root().display());

        // Collect all CSV files in the directory
        let mut csv_files = Vec::new();
        for entry in fs::read_dir(data_path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().and_then(|e| e.to_str()) == Some("csv") {
                csv_files.push(entry.path());
            }
        }

        return csv_files;
    }

    fn get_progress_bar(
        num_repeats: u64,
        exp: &EvalExperiment,
        baseline: &EvalBaseline,
        workflow: &str,
    ) -> ProgressBar {
        let pb = ProgressBar::new(num_repeats);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
                .expect("invrs(eval): error creating progress bar")
                .progress_chars("#>-"),
        );
        pb.set_message(format!("{exp}/{baseline}/{workflow}"));
        pb
    }

    // ------------------------------------------------------------------------
    // Run with Knative Functions
    // ------------------------------------------------------------------------

    fn get_kubectl_cmd() -> String {
        // For the moment, we literally run the `kubectl` command installed
        // as part of `coco-serverless`. We may change this in the future
        match env::var("COCO_SOURCE") {
            Ok(value) => format!("{value}/bin/kubectl"),
            Err(_) => panic!("invrs(eval): failed to read COCO_SOURCE env. var"),
        }
    }

    fn run_kubectl_cmd(cmd: &str) -> String {
        debug!("{}(eval): running kubectl command: {cmd}", Env::SYS_NAME);
        let args: Vec<&str> = cmd.split_whitespace().collect();

        let output = Command::new(Self::get_kubectl_cmd())
            .args(&args[0..])
            .output()
            .expect("invrs(eval): failed to execute kubectl command");

        String::from_utf8(output.stdout)
            .expect("invrs(eval): failed to convert kube command output to string")
    }

    fn wait_for_pods(namespace: &str, label: &str, num_expected: usize) {
        loop {
            thread::sleep(time::Duration::from_secs(2));

            let output = Self::run_kubectl_cmd(&format!("-n {namespace} get pods -l {label} -o jsonpath='{{..status.conditions[?(@.type==\"Ready\")].status}}'"));
            let values: Vec<&str> = output.split_whitespace().collect();

            debug!(
                "{}(eval): waiting for {num_expected} pods (label: {label}) to be ready...",
                Env::SYS_NAME
            );
            if values.len() != num_expected {
                debug!(
                    "{}(eval): not enough pods: {} != {num_expected}",
                    Env::SYS_NAME,
                    values.len()
                );
                continue;
            }

            if !values.iter().all(|&item| item == "'True'") {
                debug!("{}(eval): not enough pods in 'Ready' state", Env::SYS_NAME);
                continue;
            }

            break;
        }
    }

    fn wait_for_pod(namespace: &str, label: &str) {
        Self::wait_for_pods(namespace, label, 1);
    }

    fn template_yaml(yaml_path: PathBuf, env_vars: BTreeMap<&str, &str>) -> String {
        let yaml_content = fs::read_to_string(yaml_path).expect("invrs(eval): failed to read yaml");

        // Use envsubst to substitute environment variables in the YAML
        let mut envsubst_cmd = Command::new("envsubst");
        for (key, value) in &env_vars {
            envsubst_cmd.env(key, value);
        }

        let mut envsubst = envsubst_cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("invrs(eval): failed to start envsubst");

        envsubst
            .stdin
            .as_mut()
            .expect("invrs(eval): failed to open stdin for envsubst")
            .write_all(yaml_content.as_bytes())
            .expect("invrs(eval): failed to write to envsubst");

        // Collect the output (substituted YAML)
        let result = envsubst
            .wait_with_output()
            .expect("invrs(eval): failed to read envsubst result");

        String::from_utf8(result.stdout).expect("Failed to convert envsubst output to string")
    }

    fn deploy_workflow(workflow: &AvailableWorkflow, exp: &EvalExperiment, baseline: &EvalBaseline) {
        let workflow_yaml = match exp {
            EvalExperiment::ColdStart => {
                Env::proj_root().join("ubench").join("cold-start").join("service.yaml")
            }
            _ => {
                Workflows::get_root().join(format!("{workflow}")).join("knative").join("workflow.yaml")
            }
        };
        let templated_yaml = Self::template_yaml(
            workflow_yaml,
            BTreeMap::from([
                (
                    "RUNTIME_CLASS_NAME",
                    match baseline {
                        EvalBaseline::Knative => "kata-qemu",
                        EvalBaseline::SnpKnative | EvalBaseline::AcclessKnative => "kata-qemu-snp-sc2",
                        _ => panic!("woops"),
                    },
                ),
                ("ACCLESS_VERSION", &env::var("ACCLESS_VERSION").unwrap()),
                (
                    "ACCLESS_MODE",
                    match baseline {
                        EvalBaseline::Knative | EvalBaseline::SnpKnative => "off",
                        EvalBaseline::AcclessKnative => "on",
                        _ => panic!("woops"),
                    },
                ),
            ]),
        );

        let mut kubectl = Command::new(Self::get_kubectl_cmd())
            .arg("apply")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("invrs(eval): failed to start kubectl apply");

        kubectl
            .stdin
            .as_mut()
            .expect("invrs(eval): failed to open stdin for kubectl")
            .write_all(templated_yaml.as_bytes())
            .expect("invrs(eval): failed to feed kubectl through stdin");

        // Check if the kubectl command succeeded
        kubectl
            .wait_with_output()
            .expect("invrs(eval): failed to run kubectl command");

        thread::sleep(time::Duration::from_secs(2));
    }

    fn delete_workflow(workflow: &AvailableWorkflow, exp: &EvalExperiment, baseline: &EvalBaseline) {
        let workflow_yaml = match exp {
            EvalExperiment::ColdStart => {
                Env::proj_root().join("ubench").join("cold-start").join("service.yaml")
            }
            _ => {
                Workflows::get_root().join(format!("{workflow}")).join("knative").join("workflow.yaml")
            }
        };
        let templated_yaml = Self::template_yaml(
            workflow_yaml,
            BTreeMap::from([
                (
                    "RUNTIME_CLASS_NAME",
                    match baseline {
                        EvalBaseline::Knative => "kata-qemu",
                        EvalBaseline::SnpKnative | EvalBaseline::AcclessKnative => "kata-qemu-snp-sc2",
                        _ => panic!("woops"),
                    },
                ),
                ("TLESS_VERSION", &Env::get_version().unwrap()),
                (
                    "ACCLESS_MODE",
                    match baseline {
                        EvalBaseline::Knative | EvalBaseline::SnpKnative => "off",
                        EvalBaseline::AcclessKnative => "on",
                        _ => panic!("woops"),
                    },
                ),
            ]),
        );

        let mut kubectl = Command::new(Self::get_kubectl_cmd())
            .arg("delete")
            .arg("--wait=true")
            .arg("--cascade=foreground")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("invrs(eval): failed to start kubectl apply");

        kubectl
            .stdin
            .as_mut()
            .expect("invrs(eval): failed to open stdin for kubectl")
            .write_all(templated_yaml.as_bytes())
            .expect("invrs(eval): failed to feed kubectl through stdin");

        kubectl
            .wait_with_output()
            .expect("invrs(eval): failed to run kubectl command");
    }

    async fn wait_for_scale_to_zero() {
        loop {
            let output = Self::run_kubectl_cmd(&format!("-n accless get pods -o jsonpath={{..status.conditions[?(@.type==\"Ready\")].status}}"));
            debug!("invrs: waiting for a scale-down: out: {output}");
            let values: Vec<&str> = output.split_whitespace().collect();

            // One pod corresponds to the MinIO service
            if values.len() == 1 {
                break;
            }

            thread::sleep(time::Duration::from_secs(2));
        }
    }

    /// Run workflow once, and return result depending on the experiment
    async fn run_workflow_once(
        workflow: &AvailableWorkflow,
        exp: &EvalExperiment,
        scale_up_factor: u32,
    ) -> ExecutionResult {
        let mut exp_result = ExecutionResult {
            start_time: Utc::now(),
            end_time: Utc::now(),
            iter: 0,
        };

        // Common trigger mechanism
        let mut trigger_cmd = Workflows::get_root();
        trigger_cmd.push(format!("{workflow}"));
        trigger_cmd.push("knative");
        trigger_cmd.push("curl_cmd.sh");
        let output = match exp {
            EvalExperiment::ScaleUpLatency => Command::new(trigger_cmd.clone())
                .env("OVERRIDE_NUM_AUDIT_FUNCS", scale_up_factor.to_string())
                .output()
                .expect("invrs(eval): failed to execute trigger command"),
            EvalExperiment::ColdStart => {
                let cmd = Env::proj_root().join("ubench").join("cold-start").join("curl_cmd.sh");
                let output = Command::new(cmd.clone())
                    .output()
                    .expect("invrs(eval): failed to execute trigger command");

                // Cold-start is done here
                exp_result.end_time = Utc::now();

                output
            }
            _ => Command::new(trigger_cmd.clone())
                .output()
                .expect("invrs(eval): failed to execute trigger command"),
        };

        match output.status.code() {
            Some(0) => {
                debug!("{trigger_cmd:?}: executed succesfully");
            }
            Some(code) => {
                let stderr =
                    str::from_utf8(&output.stderr).unwrap_or("invrs(eval): failed to get stderr");
                panic!("{trigger_cmd:?}: exited with error (code: {code}): {stderr}");
            }
            None => {
                let stderr =
                    str::from_utf8(&output.stderr).unwrap_or("invrs(eval): failed to get stderr");
                panic!("{trigger_cmd:?}: failed: {stderr}");
            }
        };

        // Specific per-workflow completion detection
        match workflow {
            AvailableWorkflow::Finra => {
                let result_key = format!("{workflow}/outputs/merge/results.txt");

                match S3::wait_for_key(EVAL_BUCKET_NAME, result_key.as_str()).await {
                    Some(time) => {
                        exp_result.end_time = time;
                        S3::clear_object(EVAL_BUCKET_NAME, result_key.as_str()).await;

                        // For FINRA we also need to delete two other files
                        // that we await on throughout workflow execution
                        S3::clear_object(EVAL_BUCKET_NAME, "finra/outputs/fetch-public/trades")
                            .await;
                        S3::clear_object(EVAL_BUCKET_NAME, "finra/outputs/fetch-private/portfolio")
                            .await;
                    }
                    None => error!("invrs(eval): timed-out waiting for FINRA workload to finish"),
                }
            }
            AvailableWorkflow::MlTraining => {
                let result_key = format!("{workflow}/outputs/done.txt");

                match S3::wait_for_key(EVAL_BUCKET_NAME, result_key.as_str()).await {
                    Some(time) => {
                        exp_result.end_time = time;
                        S3::clear_object(EVAL_BUCKET_NAME, result_key.as_str()).await;
                    }
                    None => {
                        error!("invrs(eval): timed-out waiting for ML training workload to finish")
                    }
                }
            }
            AvailableWorkflow::MlInference => {
                // ML Inference finishes off in a scale-out, so we need to
                // wait for as many functions as we have invoked

                match S3::wait_for_key(
                    EVAL_BUCKET_NAME,
                    format!("{workflow}/outputs/predict/done.txt").as_str(),
                )
                .await
                {
                    Some(time) => {
                        exp_result.end_time = time;
                        // Remove all the outputs directory
                        S3::clear_dir(
                            EVAL_BUCKET_NAME.to_string(),
                            "ml-inference/outputs".to_string(),
                        )
                        .await;
                    }
                    None => {
                        error!("invrs(eval): timed-out waiting for ML training workload to finish")
                    }
                }
            }
            AvailableWorkflow::WordCount => {
                if exp != &EvalExperiment::ColdStart {
                    // First wait for the result key
                    let result_key = format!("{workflow}/outputs/aggregated-results.txt");

                    match S3::wait_for_key(EVAL_BUCKET_NAME, result_key.as_str()).await {
                        Some(time) => {
                            // If succesful, remove the result key
                            exp_result.end_time = time;
                            S3::clear_object(EVAL_BUCKET_NAME, result_key.as_str()).await;
                        }
                        None => {
                            error!("invrs(eval): timed-out waiting for Word Count workload to finish")
                        }
                    }
                }
            }
        }

        // Per-experiment, per-workflow clean-up
        match exp {
            EvalExperiment::E2eLatencyCold | EvalExperiment::ColdStart => {
                debug!("invrs: {exp}: waiting for scale-to-zero...");
                Self::wait_for_scale_to_zero().await;
            }
            _ => debug!("invrs: {exp}: noting to clean-up after single execution"),
        }

        // Cautionary sleep between runs
        thread::sleep(time::Duration::from_secs(5));

        return exp_result;
    }

    async fn run_knative_experiment(
        exp: &EvalExperiment,
        args: &EvalRunArgs,
        args_offset: usize,
        scale_up_factor: u32,
    ) -> anyhow::Result<()> {
        let baseline = args.baseline[args_offset].clone();

        // First, deploy the common services
        /*
        let k8s_common_path = Env::proj_root().join("k8s").join("common.yaml");
        // k8s_common_path.push("common.yaml");
        Self::run_kubectl_cmd(&format!("apply -f {}", k8s_common_path.display()));

        // Wait for the MinIO pod to be ready
        Self::wait_for_pod("accless", "accless.workflows/name=minio");
        */

        // Get the MinIO URL
        let minio_url = Self::run_kubectl_cmd("-n accless get services -o jsonpath={.items[?(@.metadata.name==\"minio\")].spec.clusterIP}");
        unsafe {
            env::set_var("MINIO_URL", minio_url);
        }

        // Upload the state for all workflows for the experiment
        let workflow_iter = match exp {
            // For the scale-up latency, we only run the FINRA workflow
            EvalExperiment::ScaleUpLatency => [AvailableWorkflow::Finra].iter(),
            EvalExperiment::ColdStart => [AvailableWorkflow::WordCount].iter(),
            _ => AvailableWorkflow::iter_variants(),
        };

        // Execute each workload individually
        // for workflow in vec![&AvailableWorkflow::MlInference] {
        for workflow in workflow_iter.clone() {
            // Initialise result file
            Self::init_data_file(workflow, &exp, &baseline, scale_up_factor);

            // Prepare progress bar for each different experiment
            let mut workflow_str = format!("{workflow}");
            if scale_up_factor > 0 {
                workflow_str = format!("{workflow}-{scale_up_factor}");
            }
            let pb = Self::get_progress_bar(
                args.num_repeats.into(),
                exp,
                &baseline,
                workflow_str.as_str(),
            );

            Self::deploy_workflow(workflow, &exp, &baseline);

            // Do warm-up rounds
            for _ in 0..args.num_warmup_repeats {
                Self::run_workflow_once(workflow, exp, scale_up_factor).await;
            }

            // Do actual experiment
            for i in 0..args.num_repeats {
                let mut result = Self::run_workflow_once(workflow, exp, scale_up_factor).await;
                result.iter = i;
                Self::write_result_to_file(workflow, &exp, &baseline, &result, scale_up_factor);

                pb.inc(1);
            }

            // Delete workflow
            Self::delete_workflow(workflow, &exp, &baseline);

            // Finish progress bar
            pb.finish();
        }

        // Experiment-wide clean-up
        // let k8s_common_path = Env::proj_root().join("k8s").join("common.yaml");
        // Self::run_kubectl_cmd(&format!("delete -f {}", k8s_common_path.display()));

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Run with Faasm Functions
    // ------------------------------------------------------------------------

    fn run_faasmctl_cmd(cmd: &str) -> String {
        debug!("invrs(eval): executing faasmctl command: {cmd}");
        // Need to use shell_words to properly preserve double quotes
        let args = shell_words::split(cmd).unwrap();

        let output = Command::new("faasmctl")
            .args(&args[0..])
            .output()
            .expect("invrs(eval): failed to execute faasmctl command");

        let stderr = String::from_utf8(output.stderr)
            .expect("invrs(eval): failed to convert faasmctl command output to string");
        debug!("faasmctl stderr: {stderr}");

        let stdout = String::from_utf8(output.stdout)
            .expect("invrs(eval): failed to convert faasmctl command output to string");
        debug!("faasmctl stdout: {stdout}");
        stdout
    }

    fn epoch_ts_to_datetime(epoch_str: &str) -> DateTime<Utc> {
        let epoch_seconds: f64 = epoch_str.parse().unwrap();
        let secs = epoch_seconds as i64;
        let nanos = ((epoch_seconds - secs as f64) * 1_000_000_000.0) as u32;

        Utc.timestamp_opt(secs, nanos).single().unwrap()
    }

    async fn run_faasm_experiment(
        exp: &EvalExperiment,
        args: &EvalRunArgs,
        args_offset: usize,
        scale_up_factor: u32,
    ) -> anyhow::Result<()> {
        let baseline = args.baseline[args_offset].clone();

        // Work-out the MinIO URL
        let mut minio_url = Self::run_faasmctl_cmd("s3.get-url");
        minio_url = minio_url.strip_suffix("\n").unwrap().to_string();
        unsafe {
            env::set_var("MINIO_URL", minio_url);
        }

        async fn cleanup_single_execution(exp: &EvalExperiment) {
            match exp {
                EvalExperiment::E2eLatencyCold => {
                    debug!("Flushing Faasm workers and sleeping...");
                    Eval::run_faasmctl_cmd("flush.workers");
                    thread::sleep(time::Duration::from_secs(2));
                }
                _ => debug!("nothing to do"),
            }
        }

        // Work-out the workflows to execute for each experiment
        let workflow_iter = match exp {
            // For the scale-up latency, we only run the FINRA workflow
            EvalExperiment::ScaleUpLatency => [AvailableWorkflow::Finra].iter(),
            // For the cold-start experiment, we only run part of the
            // word count workflow
            EvalExperiment::ColdStart => [AvailableWorkflow::WordCount].iter(),
            _ => AvailableWorkflow::iter_variants(),
        };

        // Invoke each workflow
        for workflow in workflow_iter.clone() {
            let mut faasm_cmdline = Workflows::get_faasm_cmdline(workflow).to_string();
            if *exp == EvalExperiment::ScaleUpLatency {
                faasm_cmdline = format!("finra/yfinance.csv {scale_up_factor}");
            }

            // Initialise result file
            Self::init_data_file(workflow, &exp, &baseline, scale_up_factor);

            // Prepare progress bar for each different experiment
            let mut workflow_str = format!("{workflow}");
            if scale_up_factor > 0 {
                workflow_str = format!("{workflow}-{scale_up_factor}");
            }
            let pb = Self::get_progress_bar(args.num_repeats.into(), exp, &baseline, &workflow_str);

            // TODO: consider if this is the output format we want
            let mut faasmctl_cmd = format!(
                "invoke {workflow} driver --cmdline \"{faasm_cmdline}\" --output-format start-end-ts"
            );
            if *exp == EvalExperiment::ColdStart {
                faasmctl_cmd =
                    "invoke accless ubench-cold-start --output-format cold-start".to_string();
            }

            // Do warm-up rounds
            for _ in 0..args.num_warmup_repeats {
                Self::run_faasmctl_cmd(&faasmctl_cmd);
                cleanup_single_execution(exp).await;
            }

            // Do actual experiment
            for i in 0..args.num_repeats {
                let mut output = Self::run_faasmctl_cmd(&faasmctl_cmd);
                output = output.strip_suffix("\n").unwrap().to_string();
                let result = match exp {
                    // The cold-start experiment needs ms-scale resolution
                    // for fine-grained measurement
                    EvalExperiment::ColdStart => {
                        let now = Utc::now();
                        let time_f64: f64 = output.parse().expect("Invalid float");
                        let chrono_duration =
                            chrono::Duration::microseconds((time_f64 * 1000.0).round() as i64);

                        ExecutionResult {
                            start_time: now,
                            end_time: now + chrono_duration,
                            iter: i,
                        }
                    }
                    _ => {
                        let ts = output.split(",").collect::<Vec<&str>>();
                        ExecutionResult {
                            start_time: Self::epoch_ts_to_datetime(ts[0]),
                            end_time: Self::epoch_ts_to_datetime(ts[1]),
                            iter: i,
                        }
                    }
                };

                Self::write_result_to_file(workflow, &exp, &baseline, &result, scale_up_factor);

                // Clean-up
                cleanup_single_execution(exp).await;

                pb.inc(1);
            }

            // Finish progress bar
            pb.finish();
        }

        Ok(())
    }

    pub async fn run(exp: &EvalExperiment, args: &EvalRunArgs) -> anyhow::Result<()> {
        for i in 0..args.baseline.len() {
            match args.baseline[i] {
                EvalBaseline::Knative | EvalBaseline::SnpKnative | EvalBaseline::AcclessKnative => {
                    match exp {
                        EvalExperiment::ScaleUpLatency => {
                            // for scale_up_factor in 1..(args.scale_up_range + 1) {
                            for scale_up_factor in vec![1, 7, 8, 9, 10] {
                                Self::run_knative_experiment(exp, args, i, scale_up_factor).await?;
                            }
                        }
                        _ => Self::run_knative_experiment(exp, args, i, 0).await?,
                    }
                }
                EvalBaseline::Faasm | EvalBaseline::SgxFaasm | EvalBaseline::AcclessFaasm => {
                    match exp {
                        EvalExperiment::ScaleUpLatency => {
                            for scale_up_factor in 1..(args.scale_up_range + 1) {
                                Self::run_faasm_experiment(exp, args, i, scale_up_factor).await?;
                            }
                        }
                        _ => Self::run_faasm_experiment(exp, args, i, 0).await?,
                    }
                }
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------------
    // Plotting Functions
    // ------------------------------------------------------------------------

    fn is_faasm_baseline(baseline: &EvalBaseline) -> bool {
        match baseline {
            EvalBaseline::Knative | EvalBaseline::SnpKnative | EvalBaseline::AcclessKnative => {
                false
            }
            EvalBaseline::Faasm | EvalBaseline::SgxFaasm | EvalBaseline::AcclessFaasm => true,
        }
    }

    fn plot_e2e_latency(exp: &EvalExperiment, data_files: &Vec<PathBuf>) -> anyhow::Result<()> {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Record {
            #[allow(dead_code)]
            run: u32,
            time_ms: u64,
        }

        // Initialize the structure to hold the data
        let mut data = BTreeMap::<AvailableWorkflow, BTreeMap<EvalBaseline, f64>>::new();
        for workflow in AvailableWorkflow::iter_variants() {
            let mut inner_map = BTreeMap::<EvalBaseline, f64>::new();
            for baseline in EvalBaseline::iter_variants() {
                inner_map.insert(baseline.clone(), 0.0);
            }
            data.insert(workflow.clone(), inner_map);
        }

        let num_workflows = AvailableWorkflow::iter_variants().len();
        let num_baselines = EvalBaseline::iter_variants().len();
        let mut y_max = 0.0;
        // Each bar has width 1 and we add padding bars between workflows
        let x_max = num_baselines * num_workflows + num_workflows + 1;

        // Collect data
        for csv_file in data_files {
            let file_name = csv_file
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or_default();
            let file_name_len = file_name.len();
            let file_name_no_ext = &file_name[0..file_name_len - 4];

            let wflow: AvailableWorkflow = file_name_no_ext.split("_").collect::<Vec<&str>>()[1]
                .parse()
                .unwrap();
            let baseline: EvalBaseline = file_name_no_ext.split("_").collect::<Vec<&str>>()[0]
                .parse()
                .unwrap();

            // Open the CSV and deserialize records
            let mut reader = ReaderBuilder::new()
                .has_headers(true)
                .from_path(csv_file)
                .unwrap();
            let mut total_time = 0;
            let mut count = 0;

            for result in reader.deserialize() {
                let record: Record = result.unwrap();
                total_time += record.time_ms;
                count += 1;
            }

            let average_time = data.get_mut(&wflow).unwrap().get_mut(&baseline).unwrap();
            *average_time = total_time as f64 / count as f64;

            if *average_time > y_max {
                y_max = *average_time;
            }
        }

        let mut plot_path = env::current_dir().expect("invrs: failed to get current directory");
        plot_path.push("eval");
        plot_path.push(format!("{exp}"));
        plot_path.push("plots");
        plot_path.push(format!("{}.svg", exp.to_string().replace("-", "_")));

        // Plot data
        let root = SVGBackend::new(&plot_path, (800, 300)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .margin_top(40)
            .build_cartesian_2d(0..x_max, 0f64..5f64)
            .unwrap();

        chart
            .configure_mesh()
            // .y_desc("Slowdown vs Non-Confidential")
            .y_label_style(("sans-serif", 20).into_font()) // Set y-axis label font and size
            .x_desc("")
            // .x_labels(0)
            .x_label_formatter(&|_| format!(""))
            .y_labels(10)
            .disable_x_mesh()
            .disable_x_axis()
            .y_label_formatter(&|y| format!("{:.0}", y))
            /*
            .light_line_style(ShapeStyle {
                color: RGBColor(200, 200, 200).to_rgba().mix(0.5),
                filled: true,
                stroke_width: 1,
            })
            */
            .draw()
            .unwrap();

        // Manually draw the y-axis label with a custom font and size
        root.draw(&Text::new(
            "Slowdown (vs non-confidential)",
            (5, 260),
            ("sans-serif", 20)
                .into_font()
                .transform(FontTransform::Rotate270)
                .color(&BLACK),
        ))
        .unwrap();

        // Draw bars
        for (w_idx, (workflow, workflow_data)) in data.iter().enumerate() {
            let x_orig = w_idx * (num_baselines + 1);

            // Work-out the slowest value for each set of baselines
            let y_faasm: f64 = *workflow_data.get(&EvalBaseline::Faasm).unwrap();
            let y_knative: f64 = *workflow_data.get(&EvalBaseline::Knative).unwrap();

            /* Un-comment to print the overhead claimed in the paper
            println!("{workflow}: knative overhead: {:.2} %",
                     ((*workflow_data.get(&EvalBaseline::TlessKnative).unwrap() /
                     *workflow_data.get(&EvalBaseline::CcKnative).unwrap()) - 1.0) * 100.0
                    );
            if *workflow == AvailableWorkflow::MlInference {
                println!("{} vs {}",
                     *workflow_data.get(&EvalBaseline::TlessKnative).unwrap(),
                     *workflow_data.get(&EvalBaseline::CcKnative).unwrap());
            }
            println!("{workflow}: faasm overhead: {:.2} %",
                     ((*workflow_data.get(&EvalBaseline::TlessFaasm).unwrap() /
                     *workflow_data.get(&EvalBaseline::SgxFaasm).unwrap()) - 1.0) * 100.0
                    );
            */

            chart
                .draw_series((0..).zip(workflow_data.iter()).map(|(x, (baseline, y))| {
                    // Bar style
                    let bar_style = ShapeStyle {
                        color: baseline.get_color().into(),
                        filled: true,
                        stroke_width: 2,
                    };

                    let this_y;
                    if Self::is_faasm_baseline(baseline) {
                        this_y = (y / y_faasm) as f64;
                    } else {
                        this_y = (y / y_knative) as f64;
                    }

                    let mut bar = Rectangle::new(
                        [(x_orig + x, 0 as f64), (x_orig + x + 1, this_y as f64)],
                        bar_style,
                    );
                    bar.set_margin(0, 0, 2, 2);
                    bar
                }))
                .unwrap();

            for (x, (baseline, y)) in (0..).zip(workflow_data.iter()) {
                let this_y;
                if Self::is_faasm_baseline(baseline) {
                    this_y = (y / y_faasm) as f64;
                } else {
                    this_y = (y / y_knative) as f64;
                }

                // Add text
                let y_offset = match this_y > 5.0 {
                    true => -0.1,
                    false => 0.25,
                };
                chart
                    .plotting_area()
                    .draw(&Text::new(
                        format!("{:.1}", this_y),
                        (x_orig + x, (this_y + y_offset) as f64),
                        ("sans-serif", 15).into_font(),
                    ))
                    .unwrap();
            }

            // Add label for the workflow
            let x_workflow_label = x_orig + num_baselines / 2 - 1;
            let label_px_coordinate = chart
                .plotting_area()
                .map_coordinate(&(x_workflow_label, -0.25));
            root.draw(&Text::new(
                format!("{workflow}"),
                label_px_coordinate,
                ("sans-serif", 20).into_font(),
            ))
            .unwrap();
        }

        // Add solid frames
        // TODO: we could add whitespaces in the horizontal lines
        chart
            .plotting_area()
            .draw(&PathElement::new(
                vec![(0, 100 as f64), (x_max, 100 as f64)],
                &BLACK,
            ))
            .unwrap();
        chart
            .plotting_area()
            .draw(&PathElement::new(
                vec![(x_max, 0 as f64), (x_max, 100 as f64)],
                &BLACK,
            ))
            .unwrap();
        chart
            .plotting_area()
            .draw(&PathElement::new(
                vec![(0, 0 as f64), (x_max, 0 as f64)],
                &BLACK,
            ))
            .unwrap();

        // Manually draw the legend outside the grid, above the chart
        let legend_x_start = 50;
        let legend_y_pos = 6; // Position above the chart

        for (idx, baseline) in EvalBaseline::iter_variants().enumerate() {
            // Calculate position for each legend item
            let x_pos = legend_x_start + idx as i32 * 120;
            let y_pos = legend_y_pos;

            // Draw the color box (Rectangle)
            root.draw(&Rectangle::new(
                [(x_pos, y_pos), (x_pos + 20, y_pos + 20)],
                baseline.get_color().filled(),
            ))
            .unwrap();

            let mut label = format!("{baseline}");
            if baseline == &EvalBaseline::SnpKnative {
                label = "sev-knative".to_string();
            }

            // Draw the baseline label (Text)
            root.draw(&Text::new(
                label,
                (x_pos + 30, y_pos + 5), // Adjust text position
                ("sans-serif", 20).into_font(),
            ))
            .unwrap();
        }

        root.present()?;

        Ok(())
    }

    fn plot_scale_up_latency(data_files: &Vec<PathBuf>) {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Record {
            #[allow(dead_code)]
            run: u32,
            time_ms: u64,
        }

        const NUM_MAX_FUNCS: usize = 10;

        // Collect data
        let mut data = BTreeMap::<EvalBaseline, [u64; NUM_MAX_FUNCS]>::new();
        for baseline in EvalBaseline::iter_variants() {
            data.insert(baseline.clone(), [0; NUM_MAX_FUNCS]);
        }

        for csv_file in data_files {
            let file_name = csv_file
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or_default();
            let file_name_len = file_name.len();
            let file_name_no_ext = &file_name[0..file_name_len - 4];
            let parts: Vec<&str> = file_name_no_ext.split("_").collect();
            let workload_parts: Vec<&str> = parts[1].split("-").collect();

            let baseline: EvalBaseline = parts[0].parse().unwrap();
            let _workload: &str = workload_parts[0];
            let scale_up_factor: usize = workload_parts[1].parse().unwrap();

            // Open the CSV and deserialize records
            let mut reader = ReaderBuilder::new()
                .has_headers(true)
                .from_path(csv_file)
                .unwrap();
            let mut count = 0;
            let avg_times = data.get_mut(&baseline).unwrap();

            for result in reader.deserialize() {
                let record: Record = result.unwrap();

                avg_times[scale_up_factor - 1] += record.time_ms;
                count += 1;
            }

            avg_times[scale_up_factor - 1] = avg_times[scale_up_factor - 1] / count;
        }

        let y_max: f64 = 200.0;
        let mut plot_path = Env::proj_root();
        plot_path.push("eval");
        plot_path.push(format!("{}", EvalExperiment::ScaleUpLatency));
        plot_path.push("plots");
        fs::create_dir_all(plot_path.clone()).unwrap();
        plot_path.push(format!(
            "{}.svg",
            EvalExperiment::ScaleUpLatency.to_string().replace("-", "_")
        ));

        // Plot data
        let root = SVGBackend::new(&plot_path, (800, 300)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .margin_top(40)
            .margin_left(40)
            .build_cartesian_2d(0..(NUM_MAX_FUNCS) as u32, 0f64..y_max as f64)
            .unwrap();

        chart
            .configure_mesh()
            .x_label_style(("sans-serif", 20).into_font())
            .y_label_style(("sans-serif", 20).into_font())
            .x_desc("")
            .y_label_formatter(&|y| format!("{:.0}", y))
            .draw()
            .unwrap();

        // Add solid frames
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(0, y_max), (10, y_max)], &BLACK))
            .unwrap();
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(10, 0.0), (10, y_max)], &BLACK))
            .unwrap();

        // Manually draw the X/Y-axis label with a custom font and size
        root.draw(&Text::new(
            "Execution time [s]",
            (5, 220),
            ("sans-serif", 20)
                .into_font()
                .transform(FontTransform::Rotate270)
                .color(&BLACK),
        ))
        .unwrap();
        root.draw(&Text::new(
            "# of audit functions",
            (400, 280),
            ("sans-serif", 20).into_font().color(&BLACK),
        ))
        .unwrap();

        for (baseline, values) in data {
            chart
                .draw_series(LineSeries::new(
                    (0..values.len())
                        .zip(values.iter())
                        .map(|(x, y)| ((x + 1) as u32, *y as f64 / 1000.0)),
                    baseline.get_color().stroke_width(3),
                ))
                .unwrap();

            chart
                .draw_series((0..values.len()).zip(values.iter()).map(|(x, y)| {
                    Circle::new(
                        ((x + 1) as u32, *y as f64 / 1000.0),
                        5,
                        baseline.get_color().filled(),
                    )
                }))
                .unwrap();
        }

        fn legend_label_pos_for_baseline(baseline: &EvalBaseline) -> (i32, i32) {
            let legend_x_start = 70;
            let legend_y_pos = 6;

            match baseline {
                EvalBaseline::Faasm => (legend_x_start, legend_y_pos),
                EvalBaseline::SgxFaasm => (legend_x_start + 100, legend_y_pos),
                EvalBaseline::AcclessFaasm => (legend_x_start + 220, legend_y_pos),
                EvalBaseline::Knative => (legend_x_start + 350, legend_y_pos),
                EvalBaseline::SnpKnative => (legend_x_start + 450, legend_y_pos),
                EvalBaseline::AcclessKnative => (legend_x_start + 580, legend_y_pos),
            }
        }

        for baseline in EvalBaseline::iter_variants() {
            // Calculate position for each legend item
            let (x_pos, y_pos) = legend_label_pos_for_baseline(&baseline);

            // Draw the color box (Rectangle)
            root.draw(&Rectangle::new(
                [(x_pos, y_pos), (x_pos + 20, y_pos + 20)],
                baseline.get_color().filled(),
            ))
            .unwrap();

            let mut label = format!("{baseline}");
            if baseline == &EvalBaseline::SnpKnative {
                label = "sev-knative".to_string();
            }

            // Draw the baseline label (Text)
            root.draw(&Text::new(
                label,
                (x_pos + 30, y_pos + 5),
                ("sans-serif", 20).into_font(),
            ))
            .unwrap();
        }

        root.present().unwrap();
    }

    fn compute_cdf(samples: &Vec<u64>) -> Vec<(f64, f64)> {
        let mut sorted = samples.clone();
        sorted.sort_unstable(); // more efficient for simple types like u64

        let n = sorted.len() as f64;
        sorted
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                let cdf = (i + 1) as f64 / n;
                (x as f64, cdf)
            })
            .collect()
    }

    fn plot_cold_start_cdf(plot_version: &str, data_files: &Vec<PathBuf>) {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Record {
            #[allow(dead_code)]
            run: usize,
            time_ms: u64,
        }

        let baselines = match plot_version {
            "faasm" => {
                vec![
                    EvalBaseline::Faasm,
                    EvalBaseline::SgxFaasm,
                    EvalBaseline::AcclessFaasm,
                ]
            }
            "knative" => {
                vec![
                    EvalBaseline::Knative,
                    EvalBaseline::SnpKnative,
                    EvalBaseline::AcclessKnative,
                ]
            }
            _ => {
                unreachable! {}
            }
        };

        // Collect data
        let mut data = BTreeMap::<EvalBaseline, Vec<u64>>::new();
        for baseline in &baselines {
            data.insert(baseline.clone(), vec![]);
        }

        for csv_file in data_files {
            let file_name = csv_file
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or_default();
            debug!("file name: {file_name}");

            let file_name_len = file_name.len();
            let baseline: EvalBaseline = file_name[0..file_name_len - 4].parse().unwrap();
            if !baselines.contains(&baseline) {
                continue;
            }

            // Open the CSV and deserialize records
            let mut reader = ReaderBuilder::new()
                .has_headers(true)
                .from_path(csv_file)
                .unwrap();

            for result in reader.deserialize() {
                debug!("{baseline}: {csv_file:?}");
                let record: Record = result.unwrap();
                data.get_mut(&baseline).unwrap().push(record.time_ms);
            }
        }

        let mut plot_path = Env::proj_root();
        plot_path.push("eval");
        plot_path.push(format!("{}", EvalExperiment::ColdStart));
        plot_path.push("plots");
        fs::create_dir_all(plot_path.clone()).unwrap();
        plot_path.push(format!("{plot_version}.svg"));

        // Plot data
        let root = SVGBackend::new(&plot_path, (400, 300)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        // X axis in ms
        let x_max = match plot_version {
            "faasm" => 2000,
            "knative" => 20000,
            _ => panic!(),
        };
        let y_max: f64 = 100.0;
        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .margin_top(50)
            .margin_left(40)
            .margin_right(25)
            .margin_bottom(20)
            .build_cartesian_2d((0..x_max).log_scale(), 0f64..y_max as f64)
            .unwrap();

        chart
            .configure_mesh()
            .light_line_style(&WHITE)
            .x_labels(8)
            .y_labels(6)
            .y_label_formatter(&|v| format!("{:.0}", v))
            .x_label_style(("sans-serif", FONT_SIZE).into_font())
            .y_label_style(("sans-serif", FONT_SIZE).into_font())
            .x_desc("")
            .draw()
            .unwrap();

        // Manually draw the X/Y-axis label with a custom font and size
        root.draw(&Text::new(
            "CDF [%]",
            (5, 200),
            ("sans-serif", FONT_SIZE)
                .into_font()
                .transform(FontTransform::Rotate270)
                .color(&BLACK),
        ))
        .unwrap();
        root.draw(&Text::new(
            "Latency [ms]",
            (175, 275),
            ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
        ))
        .unwrap();

        for (baseline, values) in data {
            // Draw line
            let values_cdf = Self::compute_cdf(&values);
            chart
                .draw_series(LineSeries::new(
                    values_cdf.into_iter().map(|(x, y)| (x as i32, y * 100.0)),
                    EvalBaseline::get_color(&baseline).stroke_width(5),
                ))
                .unwrap();
        }

        // Add solid frames
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(0, y_max), (x_max, y_max)], &BLACK))
            .unwrap();
        chart
            .plotting_area()
            .draw(&PathElement::new(
                vec![(x_max, 0.0), (x_max, y_max)],
                &BLACK,
            ))
            .unwrap();

        fn legend_label_pos_for_baseline(baseline: &EvalBaseline) -> (i32, i32) {
            let legend_x_start = 10;
            let legend_y_pos = 6;

            match baseline {
                EvalBaseline::Faasm => (legend_x_start, legend_y_pos),
                EvalBaseline::SgxFaasm => (legend_x_start + 110, legend_y_pos),
                EvalBaseline::AcclessFaasm => (legend_x_start + 270, legend_y_pos),
                EvalBaseline::Knative => (legend_x_start, legend_y_pos),
                EvalBaseline::SnpKnative => (legend_x_start + 110, legend_y_pos),
                EvalBaseline::AcclessKnative => (legend_x_start + 270, legend_y_pos),
            }
        }

        // for id_x in 0..EscrowBaseline::iter_variants().len() {
        for baseline in &baselines {
            // Calculate position for each legend item
            let (x_pos, y_pos) = legend_label_pos_for_baseline(&baseline);

            // Draw the color box (Rectangle) + frame
            let square_side = 20;
            root.draw(&Rectangle::new(
                [(x_pos, y_pos), (x_pos + square_side, y_pos + square_side)],
                EvalBaseline::get_color(&baseline).filled(),
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos), (x_pos + 20, y_pos)],
                &BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos + 20, y_pos), (x_pos + 20, y_pos + 20)],
                &BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos), (x_pos, y_pos + 20)],
                &BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos + 20), (x_pos + 20, y_pos + 20)],
                &BLACK,
            ))
            .unwrap();

            // Draw the baseline label (Text)
            root.draw(&Text::new(
                match baseline {
                    EvalBaseline::AcclessFaasm | EvalBaseline::AcclessKnative => format!("accless"),
                    _ => format!("{baseline}"),
                },
                (x_pos + 30, y_pos + 2), // Adjust text position
                ("sans-serif", FONT_SIZE).into_font(),
            ))
            .unwrap();
        }

        root.present().unwrap();
        println!("invrs: generated plot at: {}", plot_path.display());
    }

    pub fn plot(exp: &EvalExperiment) -> anyhow::Result<()> {
        // First, get all the data files
        let data_files = Self::get_all_data_files(exp);

        match exp {
            EvalExperiment::ColdStart => {
                // Self::plot_cold_start_cdf("faasm", &data_files);
                Self::plot_cold_start_cdf("knative", &data_files);
            }
            EvalExperiment::E2eLatency => {
                Self::plot_e2e_latency(&exp, &data_files)?;
            }
            EvalExperiment::E2eLatencyCold => {
                Self::plot_e2e_latency(&exp, &data_files)?;
            }
            EvalExperiment::ScaleUpLatency => {
                Self::plot_scale_up_latency(&data_files);
            }
        }

        Ok(())
    }

    pub async fn upload_state(eval: &EvalExperiment, system: &str) -> anyhow::Result<()> {
        // Get the MinIO URL
        let minio_url = S3::get_url(system);
        unsafe {
            env::set_var("MINIO_URL", minio_url);
            env::set_var("AS_URL", "https://146.179.4.33:8443");
        }

        // Work-out the workflows to execute for each experiment
        let workflow_iter = match eval {
            // For the scale-up latency, we only run the FINRA workflow
            EvalExperiment::ScaleUpLatency => [AvailableWorkflow::Finra].iter(),
            // For the cold-start experiment, we only run part of the
            // word count workflow, but we don't need any state
            EvalExperiment::ColdStart => [AvailableWorkflow::WordCount].iter(),
            _ => AvailableWorkflow::iter_variants(),
        };

        // Upload the state for all workflows
        for workflow in workflow_iter.clone() {
            println!("uploading state for workflow: {workflow}");
            Workflows::upload_workflow_state(
                workflow,
                EVAL_BUCKET_NAME,
                true,
                // For cold start, we only need to upload the DAG
                match eval {
                    EvalExperiment::ColdStart => true,
                    _ => false,
                },
            )
            .await?;
        }

        Ok(())
    }

    pub fn upload_wasm(eval: &EvalExperiment) -> anyhow::Result<()> {
        // Upload state for different workflows from the experiments container
        let docker_tag = Docker::get_docker_tag(&DockerContainer::Experiments);

        match eval {
            EvalExperiment::ColdStart => {
                let ctr_path = format!("/code/tless/ubench/build-wasm/accless-ubench-cold-start");

                Self::run_faasmctl_cmd(
                    &format!("upload accless ubench-cold-start {docker_tag}:{ctr_path}")
                        .to_string(),
                );
            }
            EvalExperiment::E2eLatency | EvalExperiment::E2eLatencyCold => {
                for workflow in AvailableWorkflow::iter_variants() {
                    let ctr_path = format!("/usr/local/faasm/wasm/{workflow}");

                    Self::run_faasmctl_cmd(
                        &format!("upload.workflow {workflow} {docker_tag}:{ctr_path}").to_string(),
                    );
                }
            }
            EvalExperiment::ScaleUpLatency => {
                todo!();
            }
        }

        Ok(())
    }
}

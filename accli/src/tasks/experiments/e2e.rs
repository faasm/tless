use crate::{
    env::Env,
    tasks::{
        docker::{Docker, DockerContainer},
        experiments::{
            Experiment,
            baselines::SystemBaseline,
            workflows::{Workflow, Workflows},
        },
        s3::S3,
    },
};
use anyhow::Result;
use chrono::{DateTime, Duration, TimeZone, Utc};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error};
use shell_words;
use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    str, thread, time,
};

static EVAL_BUCKET_NAME: &str = "tless";

#[derive(Debug, Args)]
pub struct E2eRunArgs {
    #[arg(short, long, num_args = 1.., value_name = "BASELINE")]
    baseline: Vec<SystemBaseline>,
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

fn get_data_file_name(
    workflow: &Workflow,
    exp: &Experiment,
    baseline: &SystemBaseline,
    scale_up_factor: u32,
) -> String {
    match exp {
        Experiment::ColdStart { .. } => {
            format!(
                "{}/{exp}/data/{baseline}.csv",
                Env::experiments_root().display()
            )
        }
        _ => {
            if scale_up_factor == 0 {
                format!(
                    "{}/{exp}/data/{baseline}_{workflow}.csv",
                    Env::experiments_root().display()
                )
            } else {
                format!(
                    "{}/{exp}/data/{baseline}_{workflow}-{scale_up_factor}.csv",
                    Env::experiments_root().display()
                )
            }
        }
    }
}

fn init_data_file(
    workflow: &Workflow,
    exp: &Experiment,
    baseline: &SystemBaseline,
    scale_up_factor: u32,
) -> Result<()> {
    let file_name = get_data_file_name(workflow, exp, baseline, scale_up_factor);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&file_name)
        .map_err(|e| {
            let reason = format!("error opening file (file_name={file_name}, error={e:?})");
            error!("{reason}");
            anyhow::anyhow!(reason)
        })?;

    match exp {
        Experiment::ColdStart { .. }
        | Experiment::E2eLatency { .. }
        | Experiment::E2eLatencyCold { .. }
        | Experiment::ScaleUpLatency { .. } => {
            writeln!(file, "Run,TimeMs").map_err(|e| {
                let reason = format!("error writing to file (file_name={file_name}, error={e:?})");
                error!("{reason}");
                anyhow::anyhow!(reason)
            })?;

            Ok(())
        }
        _ => {
            error!("experiment does not belong in e2e caregory (experiment={exp})");
            anyhow::bail!("experiment does not belong in e2e caregory (experiment={exp})");
        }
    }
}

fn write_result_to_file(
    workflow: &Workflow,
    exp: &Experiment,
    baseline: &SystemBaseline,
    result: &ExecutionResult,
    scale_up_factor: u32,
) -> Result<()> {
    let file_name = get_data_file_name(workflow, exp, baseline, scale_up_factor);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(&file_name)
        .map_err(|e| {
            error!("failed to open file (file_name={file_name}, error={e:?})");
            anyhow::anyhow!("failed to open file")
        })?;
    match exp {
        Experiment::ColdStart { .. }
        | Experiment::E2eLatency { .. }
        | Experiment::E2eLatencyCold { .. }
        | Experiment::ScaleUpLatency { .. } => {
            let duration: Duration = result.end_time - result.start_time;
            writeln!(file, "{},{}", result.iter, duration.num_milliseconds()).map_err(|e| {
                error!("failed to write to file (file_name={file_name}, error={e:?})");
                anyhow::anyhow!("failed to write to file")
            })?;
            Ok(())
        }
        _ => {
            error!("experiment does not belong in e2e caregory (experiment={exp})");
            anyhow::bail!("experiment does not belong in e2e caregory (experiment={exp})");
        }
    }
}

fn get_progress_bar(
    num_repeats: u64,
    exp: &Experiment,
    baseline: &SystemBaseline,
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

    let output = Command::new(get_kubectl_cmd())
        .args(&args[0..])
        .output()
        .expect("invrs(eval): failed to execute kubectl command");

    String::from_utf8(output.stdout)
        .expect("invrs(eval): failed to convert kube command output to string")
}

#[allow(dead_code)]
fn wait_for_pods(namespace: &str, label: &str, num_expected: usize) {
    loop {
        thread::sleep(time::Duration::from_secs(2));

        let output = run_kubectl_cmd(&format!(
            "-n {namespace} get pods -l {label} -o jsonpath='{{..status.conditions[?(@.type==\"Ready\")].status}}'"
        ));
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

#[allow(dead_code)]
fn wait_for_pod(namespace: &str, label: &str) {
    wait_for_pods(namespace, label, 1);
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

fn deploy_workflow(workflow: &Workflow, exp: &Experiment, baseline: &SystemBaseline) {
    let workflow_yaml = match exp {
        Experiment::ColdStart { .. } => Env::proj_root()
            .join("ubench")
            .join("cold-start")
            .join("service.yaml"),
        _ => Workflows::get_root()
            .join(format!("{workflow}"))
            .join("knative")
            .join("workflow.yaml"),
    };
    let templated_yaml = template_yaml(
        workflow_yaml,
        BTreeMap::from([
            (
                "RUNTIME_CLASS_NAME",
                match baseline {
                    SystemBaseline::Knative => "kata-qemu",
                    SystemBaseline::SnpKnative | SystemBaseline::AcclessKnative => {
                        "kata-qemu-snp-sc2"
                    }
                    _ => panic!("woops"),
                },
            ),
            ("ACCLESS_VERSION", &env::var("ACCLESS_VERSION").unwrap()),
            (
                "ACCLESS_MODE",
                match baseline {
                    SystemBaseline::Knative | SystemBaseline::SnpKnative => "off",
                    SystemBaseline::AcclessKnative => "on",
                    _ => panic!("woops"),
                },
            ),
        ]),
    );

    let mut kubectl = Command::new(get_kubectl_cmd())
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

fn delete_workflow(workflow: &Workflow, exp: &Experiment, baseline: &SystemBaseline) {
    let workflow_yaml = match exp {
        Experiment::ColdStart { .. } => Env::proj_root()
            .join("ubench")
            .join("cold-start")
            .join("service.yaml"),
        _ => Workflows::get_root()
            .join(format!("{workflow}"))
            .join("knative")
            .join("workflow.yaml"),
    };
    let templated_yaml = template_yaml(
        workflow_yaml,
        BTreeMap::from([
            (
                "RUNTIME_CLASS_NAME",
                match baseline {
                    SystemBaseline::Knative => "kata-qemu",
                    SystemBaseline::SnpKnative | SystemBaseline::AcclessKnative => {
                        "kata-qemu-snp-sc2"
                    }
                    _ => panic!("woops"),
                },
            ),
            ("TLESS_VERSION", &Env::get_version().unwrap()),
            (
                "ACCLESS_MODE",
                match baseline {
                    SystemBaseline::Knative | SystemBaseline::SnpKnative => "off",
                    SystemBaseline::AcclessKnative => "on",
                    _ => panic!("woops"),
                },
            ),
        ]),
    );

    let mut kubectl = Command::new(get_kubectl_cmd())
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
        let output = run_kubectl_cmd(
            "-n accless get pods -o jsonpath={{..status.conditions[?(@.type==\"Ready\")].status}}",
        );
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
    workflow: &Workflow,
    exp: &Experiment,
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
        Experiment::ScaleUpLatency { .. } => Command::new(trigger_cmd.clone())
            .env("OVERRIDE_NUM_AUDIT_FUNCS", scale_up_factor.to_string())
            .output()
            .expect("invrs(eval): failed to execute trigger command"),
        Experiment::ColdStart { .. } => {
            let cmd = Env::proj_root()
                .join("ubench")
                .join("cold-start")
                .join("curl_cmd.sh");
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
        Workflow::Finra => {
            let result_key = format!("{workflow}/outputs/merge/results.txt");

            match S3::wait_for_key(EVAL_BUCKET_NAME, result_key.as_str()).await {
                Some(time) => {
                    exp_result.end_time = time;
                    S3::clear_object(EVAL_BUCKET_NAME, result_key.as_str()).await;

                    // For FINRA we also need to delete two other files
                    // that we await on throughout workflow execution
                    S3::clear_object(EVAL_BUCKET_NAME, "finra/outputs/fetch-public/trades").await;
                    S3::clear_object(EVAL_BUCKET_NAME, "finra/outputs/fetch-private/portfolio")
                        .await;
                }
                None => error!("invrs(eval): timed-out waiting for FINRA workload to finish"),
            }
        }
        Workflow::MlTraining => {
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
        Workflow::MlInference => {
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
                    S3::clear_dir(EVAL_BUCKET_NAME, "ml-inference/outputs").await;
                }
                None => {
                    error!("invrs(eval): timed-out waiting for ML training workload to finish")
                }
            }
        }
        Workflow::WordCount => {
            match exp {
                Experiment::ColdStart { .. } => {}
                _ => {
                    // First wait for the result key
                    let result_key = format!("{workflow}/outputs/aggregated-results.txt");

                    match S3::wait_for_key(EVAL_BUCKET_NAME, result_key.as_str()).await {
                        Some(time) => {
                            // If succesful, remove the result key
                            exp_result.end_time = time;
                            S3::clear_object(EVAL_BUCKET_NAME, result_key.as_str()).await;
                        }
                        None => {
                            error!("timed-out waiting for Word Count workload to finish")
                        }
                    }
                }
            }
        }
    }

    // Per-experiment, per-workflow clean-up
    match exp {
        Experiment::E2eLatencyCold { .. } | Experiment::ColdStart { .. } => {
            debug!("invrs: {exp}: waiting for scale-to-zero...");
            wait_for_scale_to_zero().await;
        }
        _ => debug!("invrs: {exp}: nothing to clean-up after single execution"),
    }

    // Cautionary sleep between runs
    thread::sleep(time::Duration::from_secs(5));

    exp_result
}

async fn run_knative_experiment(
    exp: &Experiment,
    args: &E2eRunArgs,
    args_offset: usize,
    scale_up_factor: u32,
) -> anyhow::Result<()> {
    let baseline = args.baseline[args_offset].clone();

    // Get the MinIO URL
    let minio_url = run_kubectl_cmd(
        "-n accless get services -o jsonpath={.items[?(@.metadata.name==\"minio\")].spec.clusterIP}",
    );
    unsafe {
        env::set_var("MINIO_URL", minio_url);
    }

    let workflow_iter = match exp {
        // For the scale-up latency, we only run the FINRA workflow
        Experiment::ScaleUpLatency { .. } => [Workflow::Finra].iter(),
        Experiment::ColdStart { .. } => [Workflow::WordCount].iter(),
        // TODO: remove me delete me
        // Experiment::E2eLatencyCold => [Workflow::MlInference,
        // Workflow::WordCount].iter(),
        _ => Workflow::iter_variants(),
    };

    // Execute each workload individually
    // for workflow in vec![&Workflow::MlInference] {
    for workflow in workflow_iter.clone() {
        // Initialise result file
        init_data_file(workflow, exp, &baseline, scale_up_factor)?;

        // Prepare progress bar for each different experiment
        let mut workflow_str = format!("{workflow}");
        if scale_up_factor > 0 {
            workflow_str = format!("{workflow}-{scale_up_factor}");
        }
        let pb = get_progress_bar(
            args.num_repeats.into(),
            exp,
            &baseline,
            workflow_str.as_str(),
        );

        deploy_workflow(workflow, exp, &baseline);

        // Do warm-up rounds
        for _ in 0..args.num_warmup_repeats {
            run_workflow_once(workflow, exp, scale_up_factor).await;
        }

        // Do actual experiment
        for i in 0..args.num_repeats {
            let mut result = run_workflow_once(workflow, exp, scale_up_factor).await;
            result.iter = i;
            write_result_to_file(workflow, exp, &baseline, &result, scale_up_factor)?;

            pb.inc(1);
        }

        // Delete workflow
        delete_workflow(workflow, exp, &baseline);

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
    exp: &Experiment,
    args: &E2eRunArgs,
    args_offset: usize,
    scale_up_factor: u32,
) -> anyhow::Result<()> {
    let baseline = args.baseline[args_offset].clone();

    // Work-out the MinIO URL
    let mut minio_url = run_faasmctl_cmd("s3.get-url");
    minio_url = minio_url.strip_suffix("\n").unwrap().to_string();
    unsafe {
        env::set_var("MINIO_URL", minio_url);
    }

    async fn cleanup_single_execution(exp: &Experiment) {
        match exp {
            Experiment::E2eLatencyCold { .. } => {
                debug!("Flushing Faasm workers and sleeping...");
                run_faasmctl_cmd("flush.workers");
                thread::sleep(time::Duration::from_secs(2));
            }
            _ => debug!("nothing to do"),
        }
    }

    // Work-out the workflows to execute for each experiment
    let workflow_iter = match exp {
        // For the scale-up latency, we only run the FINRA workflow
        Experiment::ScaleUpLatency { .. } => [Workflow::Finra].iter(),
        // For the cold-start experiment, we only run part of the
        // word count workflow
        Experiment::ColdStart { .. } => [Workflow::WordCount].iter(),
        _ => Workflow::iter_variants(),
    };

    // Invoke each workflow
    for workflow in workflow_iter.clone() {
        let mut faasm_cmdline = Workflows::get_faasm_cmdline(workflow).to_string();
        if let Experiment::ScaleUpLatency { .. } = exp {
            faasm_cmdline = format!("finra/yfinance.csv {scale_up_factor}");
        }

        // Initialise result file
        init_data_file(workflow, exp, &baseline, scale_up_factor)?;

        // Prepare progress bar for each different experiment
        let mut workflow_str = format!("{workflow}");
        if scale_up_factor > 0 {
            workflow_str = format!("{workflow}-{scale_up_factor}");
        }
        let pb = get_progress_bar(args.num_repeats.into(), exp, &baseline, &workflow_str);

        // TODO: consider if this is the output format we want
        let mut faasmctl_cmd = format!(
            "invoke {workflow} driver --cmdline \"{faasm_cmdline}\" --output-format start-end-ts"
        );
        if let Experiment::ColdStart { .. } = exp {
            faasmctl_cmd =
                "invoke accless ubench-cold-start --output-format cold-start".to_string();
        }

        // Do warm-up rounds
        for _ in 0..args.num_warmup_repeats {
            run_faasmctl_cmd(&faasmctl_cmd);
            cleanup_single_execution(exp).await;
        }

        // Do actual experiment
        for i in 0..args.num_repeats {
            let mut output = run_faasmctl_cmd(&faasmctl_cmd);
            output = output.strip_suffix("\n").unwrap().to_string();
            let result = match exp {
                // The cold-start experiment needs ms-scale resolution
                // for fine-grained measurement
                Experiment::ColdStart { .. } => {
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
                        start_time: epoch_ts_to_datetime(ts[0]),
                        end_time: epoch_ts_to_datetime(ts[1]),
                        iter: i,
                    }
                }
            };

            write_result_to_file(workflow, exp, &baseline, &result, scale_up_factor)?;

            // Clean-up
            cleanup_single_execution(exp).await;

            pb.inc(1);
        }

        // Finish progress bar
        pb.finish();
    }

    Ok(())
}

pub async fn run(exp: &Experiment, args: &E2eRunArgs) -> anyhow::Result<()> {
    for i in 0..args.baseline.len() {
        match args.baseline[i] {
            SystemBaseline::Knative
            | SystemBaseline::SnpKnative
            | SystemBaseline::AcclessKnative => match exp {
                Experiment::ScaleUpLatency { .. } => {
                    for scale_up_factor in 1..10 {
                        run_knative_experiment(exp, args, i, scale_up_factor).await?;
                    }
                }
                _ => run_knative_experiment(exp, args, i, 0).await?,
            },
            SystemBaseline::Faasm | SystemBaseline::SgxFaasm | SystemBaseline::AcclessFaasm => {
                match exp {
                    Experiment::ScaleUpLatency { .. } => {
                        for scale_up_factor in [1, 10, 20, 40, 50, 60, 70, 80, 90, 100] {
                            run_faasm_experiment(exp, args, i, scale_up_factor).await?;
                        }
                    }
                    _ => run_faasm_experiment(exp, args, i, 0).await?,
                }
            }
        }
    }

    Ok(())
}

pub async fn upload_state(eval: &Experiment, system: &str) -> anyhow::Result<()> {
    // Get the MinIO URL
    let minio_url = S3::get_url(system);
    // TODO: get the correct AS URL too
    unsafe {
        env::set_var("MINIO_URL", minio_url);
        env::set_var("AS_URL", "https://146.179.4.33:8443");
    }

    // Work-out the workflows to execute for each experiment
    let workflow_iter = match eval {
        // For the scale-up latency, we only run the FINRA workflow
        Experiment::ScaleUpLatency { .. } => [Workflow::Finra].iter(),
        // For the cold-start experiment, we only run part of the
        // word count workflow, but we don't need any state
        Experiment::ColdStart { .. } => [Workflow::WordCount].iter(),
        _ => Workflow::iter_variants(),
    };

    // Upload the state for all workflows
    for workflow in workflow_iter.clone() {
        println!("uploading state for workflow: {workflow}");
        Workflows::upload_workflow_state(
            workflow,
            EVAL_BUCKET_NAME,
            true,
            // For cold start, we only need to upload the DAG
            matches!(eval, Experiment::ColdStart { .. }),
        )
        .await?;
    }

    Ok(())
}

pub fn upload_wasm(eval: &Experiment) -> Result<()> {
    // Upload state for different workflows from the experiments container
    let docker_tag = Docker::get_docker_tag(&DockerContainer::Experiments);

    match eval {
        Experiment::ColdStart { .. } => {
            let ctr_path = "/code/tless/ubench/build-wasm/accless-ubench-cold-start";

            run_faasmctl_cmd(
                &format!("upload accless ubench-cold-start {docker_tag}:{ctr_path}").to_string(),
            );
        }
        Experiment::E2eLatency { .. } | Experiment::E2eLatencyCold { .. } => {
            for workflow in Workflow::iter_variants() {
                let ctr_path = format!("/usr/local/faasm/wasm/{workflow}");

                run_faasmctl_cmd(
                    &format!("upload.workflow {workflow} {docker_tag}:{ctr_path}").to_string(),
                );
            }
        }
        Experiment::ScaleUpLatency { .. } => {
            todo!();
        }
        _ => {
            error!("experiment does not belong in e2e caregory (experiment={eval})");
            anyhow::bail!("experiment does not belong in e2e caregory (experiment={eval})");
        }
    }

    Ok(())
}

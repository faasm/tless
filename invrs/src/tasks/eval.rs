use crate::tasks::s3::S3;
use crate::tasks::workflows::{AvailableWorkflow, Workflows};
use chrono::{DateTime, Duration, Utc};
use clap::{Args, ValueEnum};
use csv::ReaderBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error};
use plotters::prelude::*;
use serde::Deserialize;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::{collections::BTreeMap, env, fmt, fs, io::Write, thread, time};

static EVAL_BUCKET_NAME: &str = "tless";

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
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

impl FromStr for EvalBaseline {
    type Err = ();

    fn from_str(input: &str) -> Result<EvalBaseline, Self::Err> {
        match input {
            "faasm" => Ok(EvalBaseline::Faasm),
            "sgx-faasm" => Ok(EvalBaseline::SgxFaasm),
            "tless-faasm" => Ok(EvalBaseline::TlessFaasm),
            "knative" => Ok(EvalBaseline::Knative),
            "cc-knative" => Ok(EvalBaseline::CcKnative),
            "tless-knative" => Ok(EvalBaseline::TlessKnative),
            _ => Err(()),
        }
    }
}

impl EvalBaseline {
    pub fn iter_variants() -> std::slice::Iter<'static, EvalBaseline> {
        static VARIANTS: [EvalBaseline; 6] = [
            EvalBaseline::Faasm,
            EvalBaseline::SgxFaasm,
            EvalBaseline::TlessFaasm,
            EvalBaseline::Knative,
            EvalBaseline::CcKnative,
            EvalBaseline::TlessKnative,
        ];
        VARIANTS.iter()
    }

    pub fn get_color(&self) -> RGBColor {
        match self {
            EvalBaseline::Faasm => RGBColor(171, 222, 230),
            EvalBaseline::SgxFaasm => RGBColor(203, 170, 203),
            EvalBaseline::TlessFaasm => RGBColor(255, 255, 181),
            EvalBaseline::Knative => RGBColor(255, 204, 182),
            EvalBaseline::CcKnative => RGBColor(243, 176, 195),
            EvalBaseline::TlessKnative => RGBColor(151, 193, 169),
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
    #[arg(short, long, num_args = 1.., value_name = "BASELINE")]
    baseline: Vec<EvalBaseline>,
    #[arg(long, default_value = "3")]
    num_repeats: u32,
    #[arg(long, default_value = "0")]
    num_warmup_repeats: u32,
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
    ) -> String {
        format!(
            "{}/{exp}/data/{baseline}_{workflow}.csv",
            Self::get_root().display()
        )
    }

    fn init_data_file(workflow: &AvailableWorkflow, exp: &EvalExperiment, baseline: &EvalBaseline) {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(Self::get_data_file_name(workflow, exp, baseline))
            .expect("invrs(eval): failed to write to file");

        match exp {
            EvalExperiment::E2eLatency => {
                writeln!(file, "Run,TimeMs").expect("invrs(eval): failed to write to file");
            }
        }
    }

    fn write_result_to_file(
        workflow: &AvailableWorkflow,
        exp: &EvalExperiment,
        baseline: &EvalBaseline,
        result: &ExecutionResult,
    ) {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open(Self::get_data_file_name(workflow, exp, baseline))
            .expect("invrs(eval): failed to write to file");

        match exp {
            EvalExperiment::E2eLatency => {
                let duration: Duration = result.end_time - result.start_time;
                writeln!(file, "{},{}", result.iter, duration.num_milliseconds())
                    .expect("invrs(eval): failed to write to file");
            }
        }
    }

    fn get_all_data_files(exp: &EvalExperiment) -> Vec<PathBuf> {
        // TODO: change to data
        let data_path = format!("{}/{exp}/data-bup", Self::get_root().display());

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

        String::from_utf8(output.stdout)
            .expect("invrs(eval): failed to convert kube command output to string")
    }

    fn wait_for_pods(namespace: &str, label: &str, num_expected: usize) {
        loop {
            thread::sleep(time::Duration::from_secs(2));

            let output = Self::run_kubectl_cmd(&format!("-n {namespace} get pods -l {label} -o jsonpath='{{..status.conditions[?(@.type==\"Ready\")].status}}'"));
            let values: Vec<&str> = output.split_whitespace().collect();

            if values.len() != num_expected {
                debug!("invrs(eval): waiting for pods to be ready...");
                continue;
            }

            if !values.iter().all(|&item| item == "'True'") {
                debug!("invrs(eval): waiting for pods to be ready...");
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

    fn deploy_workflow(workflow: &AvailableWorkflow, baseline: &EvalBaseline) {
        let mut workflow_yaml = Workflows::get_root();
        workflow_yaml.push(format!("{workflow}"));
        workflow_yaml.push("knative");
        workflow_yaml.push("workflow.yaml");
        let templated_yaml = Self::template_yaml(
            workflow_yaml,
            BTreeMap::from([(
                "RUNTIME_CLASS_NAME",
                match baseline {
                    EvalBaseline::Knative => "kata-qemu",
                    EvalBaseline::CcKnative | EvalBaseline::TlessKnative => "kata-qemu-sev",
                    _ => panic!("woops"),
                },
            )]),
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

        // Specific per-workflow wait command
        match workflow {
            AvailableWorkflow::WordCount => {
                Self::wait_for_pod("tless", "tless.workflows/name=word-count-splitter");
                Self::wait_for_pod("tless", "tless.workflows/name=word-count-reducer");
            }
        }
    }

    fn delete_workflow(workflow: &AvailableWorkflow, baseline: &EvalBaseline) {
        // Common deploy mechanism
        let mut workflow_yaml = Workflows::get_root();
        workflow_yaml.push(format!("{workflow}"));
        workflow_yaml.push("knative");
        workflow_yaml.push("workflow.yaml");
        let templated_yaml = Self::template_yaml(
            workflow_yaml,
            BTreeMap::from([(
                "RUNTIME_CLASS_NAME",
                match baseline {
                    EvalBaseline::Knative => "kata-qemu",
                    EvalBaseline::CcKnative | EvalBaseline::TlessKnative => "kata-qemu-sev",
                    _ => panic!("woops"),
                },
            )]),
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

        // Sometimes the --cascade argument is not enough for all pods to
        // have fully disappeared, we also wait until there's only one pod
        // (minio) left
        /*
        loop {
            let output = Self::run_kubectl_cmd(&format!("-n tless get pods -o jsonpath={{..status.conditions[?(@.type==\"Ready\")].status}}"));
            println!("output: {output}");
            let values: Vec<&str> = output.split_whitespace().collect();

            if values.len() == 1 {
                break;
            }

            thread::sleep(time::Duration::from_secs(2));
        }
        */
    }

    /// Run workflow once, and return result depending on the experiment
    async fn run_workflow_once(workflow: &AvailableWorkflow) -> ExecutionResult {
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
        Command::new(trigger_cmd)
            .output()
            .expect("invrs(eval): failed to execute trigger command");

        // Specific per-workflow completion detection
        match workflow {
            AvailableWorkflow::WordCount => {
                match S3::wait_for_key(
                    EVAL_BUCKET_NAME,
                    format!("{workflow}/few-files/mapper-results/aggregated-results.txt").as_str(),
                )
                .await
                {
                    Some(time) => exp_result.end_time = time,
                    None => error!("invrs(s3): timed-out"),
                }
            }
        }

        // Specific per-workflow clean-up
        match workflow {
            AvailableWorkflow::WordCount => {
                S3::clear_dir(
                    EVAL_BUCKET_NAME.to_string(),
                    format!("{workflow}/few-files/mapper-results/"),
                )
                .await;
            }
        }

        // Cautionary sleep between runs
        thread::sleep(time::Duration::from_secs(5));

        return exp_result;
    }

    async fn run_knative_experiment(exp: &EvalExperiment, args: &EvalRunArgs, args_offset: usize) {
        let baseline = args.baseline[args_offset].clone();

        // First, deploy the common services
        let mut k8s_common_path = Workflows::get_root();
        k8s_common_path.push("k8s_common.yaml");
        Self::run_kubectl_cmd(&format!("apply -f {}", k8s_common_path.display()));

        // Wait for the MinIO pod to be ready
        Self::wait_for_pod("tless", "tless.workflows/name=minio");

        // Get the MinIO URL
        let minio_url = Self::run_kubectl_cmd("-n tless get services -o jsonpath={.items[?(@.metadata.name==\"minio\")].spec.clusterIP}");

        unsafe {
            env::set_var("MINIO_URL", minio_url);
        }

        // Upload the state for all workflows
        Workflows::upload_state(EVAL_BUCKET_NAME, true).await;

        // Execute each workload individually
        for workflow in AvailableWorkflow::iter_variants() {
            // Initialise result file
            Self::init_data_file(workflow, &exp, &baseline);

            // Prepare progress bar for each different experiment
            let pb = ProgressBar::new(args.num_repeats.into());
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
                    .expect("invrs(eval): error creating progress bar")
                    .progress_chars("#>-"),
            );
            pb.set_message(format!("{exp}/{baseline}/{workflow}"));

            // Deploy workflow
            Self::deploy_workflow(workflow, &baseline);

            // TODO: FIXME: consider differntiating between cold and warm starts!

            // Do warm-up rounds
            for _ in 0..args.num_warmup_repeats {
                Self::run_workflow_once(workflow).await;
            }

            // Do actual experiment
            for i in 0..args.num_repeats {
                let mut result = Self::run_workflow_once(workflow).await;
                result.iter = i;
                Self::write_result_to_file(workflow, &exp, &baseline, &result);

                pb.inc(1);
            }

            // Delete workflow
            Self::delete_workflow(workflow, &baseline);

            // Finish progress bar
            pb.finish();
        }

        // Experiment-wide clean-up
        let mut k8s_common_path = Workflows::get_root();
        k8s_common_path.push("k8s_common.yaml");
        Self::run_kubectl_cmd(&format!("delete -f {}", k8s_common_path.display()));
    }

    pub async fn run(exp: &EvalExperiment, args: &EvalRunArgs) {
        for i in 0..args.baseline.len() {
            match args.baseline[i] {
                EvalBaseline::Knative | EvalBaseline::CcKnative | EvalBaseline::TlessKnative => {
                    Self::run_knative_experiment(exp, args, i).await;
                }
                _ => panic!("invrs(eval): unimplemented baseline: {}", args.baseline[i]),
            }
        }
    }

    fn plot_e2e_latency(data_files: &Vec<PathBuf>) {
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
        plot_path.push(format!("{}", EvalExperiment::E2eLatency));
        plot_path.push("plots");
        plot_path.push("e2e_latency.svg");

        // Plot data
        let root = SVGBackend::new(&plot_path, (800, 600)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .build_cartesian_2d(0..x_max, 0i64..y_max as i64)
            .unwrap();

        chart
            .configure_mesh()
            .y_desc("Execution latency [ms]")
            .x_desc("")
            .y_labels(10)
            .disable_x_mesh()
            .y_label_formatter(&|y| format!("{:.0}", y))
            .light_line_style(ShapeStyle {
                color: RGBColor(200, 200, 200).to_rgba().mix(0.5),
                filled: true,
                stroke_width: 1,
            })
            .draw()
            .unwrap();

        // Draw bars
        for (w_idx, (workflow, workflow_data)) in data.iter().enumerate() {
            let x_orig = w_idx * num_baselines + 1;

            // TODO: make the color depend on the baseline
            chart
                .draw_series((0..).zip(workflow_data.iter()).map(|(x, (baseline, y))| {
                    // Bar style
                    let bar_style = ShapeStyle {
                        color: baseline.get_color().into(),
                        filled: true,
                        stroke_width: 2,
                    };
                    let mut bar =
                        Rectangle::new([(x_orig + x, 0), (x_orig + x + 1, *y as i64)], bar_style);
                    bar.set_margin(0, 0, 5, 5);
                    bar
                }))
                .unwrap();

            // Add label for the workflow
            let x_workflow_label = x_orig + num_baselines / 2;
            let label_px_coordinate = chart
                .plotting_area()
                .map_coordinate(&(x_workflow_label, -10));
            root.draw(&Text::new(
                format!("{workflow}"),
                label_px_coordinate,
                ("sans-serif", 20).into_font(),
            ))
            .unwrap();
        }

        // Add dummy lines to create entries in the legend
        for baseline in EvalBaseline::iter_variants() {
            chart
                .draw_series(std::iter::once(PathElement::new(
                    vec![(0, -10), (0, -10)],
                    baseline.get_color().stroke_width(10),
                )))
                .unwrap()
                .label(format!("{baseline}"))
                .legend(move |(x, y)| {
                    Rectangle::new([(x, y - 5), (x + 30, y + 5)], baseline.get_color().filled())
                });
        }

        // Draw the legend
        chart
            .configure_series_labels()
            .position(SeriesLabelPosition::UpperRight)
            .border_style(&BLACK)
            .background_style(&WHITE.mix(0.8))
            .draw()
            .unwrap();

        root.present().unwrap();
    }

    pub fn plot(exp: &EvalExperiment) {
        // First, get all the data files
        let data_files = Self::get_all_data_files(exp);

        match exp {
            EvalExperiment::E2eLatency => {
                Self::plot_e2e_latency(&data_files);
            }
        }
    }
}

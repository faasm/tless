use crate::env::Env;
use crate::tasks::color::{get_color_from_label, FONT_SIZE};
use anyhow::Result;
use clap::{Args, ValueEnum};
use csv::ReaderBuilder;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use log::debug;
use plotters::prelude::*;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env, fmt, fs,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    process::Command,
    str,
    str::FromStr,
    time::Instant,
};

// eDAG Verify constants
static MAX_NUM_CHAINS: u32 = 10;

const REQUEST_COUNTS_MHSM: &[usize] = &[1, 5, 10, 15, 20, 40, 60, 80, 100];
const REQUEST_COUNTS_TRUSTEE: &[usize] = &[1, 10, 50, 100, 200, 400, 600, 800, 1000];
const REQUEST_PARALLELISM: usize = 10;

pub enum MicroBenchmarks {
    EscrowXput,
    VerifyEDag,
}

impl fmt::Display for MicroBenchmarks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MicroBenchmarks::EscrowXput => write!(f, "escrow-xput"),
            MicroBenchmarks::VerifyEDag => write!(f, "verify-edag"),
        }
    }
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum EscrowBaseline {
    Trustee,
    ManagedHSM,
    AcclessMaa,
    Accless,
}

impl fmt::Display for EscrowBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EscrowBaseline::Trustee => write!(f, "trustee"),
            EscrowBaseline::ManagedHSM => write!(f, "managed-hsm"),
            EscrowBaseline::AcclessMaa => write!(f, "accless-maa"),
            EscrowBaseline::Accless => write!(f, "accless"),
        }
    }
}

impl FromStr for EscrowBaseline {
    type Err = ();

    fn from_str(input: &str) -> Result<EscrowBaseline, Self::Err> {
        match input {
            "trustee" => Ok(EscrowBaseline::Trustee),
            "managed-hsm" => Ok(EscrowBaseline::ManagedHSM),
            "accless-maa" => Ok(EscrowBaseline::AcclessMaa),
            "accless" => Ok(EscrowBaseline::Accless),
            _ => Err(()),
        }
    }
}

impl EscrowBaseline {
    const SNP_VM_CODE_DIR: &str = "/home/tless/git";

    pub fn iter_variants() -> std::slice::Iter<'static, EscrowBaseline> {
        static VARIANTS: [EscrowBaseline; 4] = [
            EscrowBaseline::Trustee,
            EscrowBaseline::ManagedHSM,
            EscrowBaseline::AcclessMaa,
            EscrowBaseline::Accless,
        ];
        VARIANTS.iter()
    }

    pub fn get_color(&self) -> RGBColor {
        match self {
            EscrowBaseline::Trustee => get_color_from_label("dark-orange"),
            EscrowBaseline::ManagedHSM => get_color_from_label("dark-green"),
            EscrowBaseline::AcclessMaa => get_color_from_label("dark-blue"),
            EscrowBaseline::Accless => get_color_from_label("accless"),
        }
    }

    // -------------------------------------------------------------------------
    // Trustee methods and constants
    // -------------------------------------------------------------------------

    const TEE: &str = "azsnpvtpm";

    fn get_work_dir() -> String {
        format!(
            "{}/confidential-containers/trustee/kbs/test/work",
            Self::SNP_VM_CODE_DIR
        )
    }

    fn get_https_cert() -> String {
        format!("{}/https.crt", Self::get_work_dir())
    }

    fn get_kbs_key() -> String {
        format!("{}/kbs.key", Self::get_work_dir())
    }

    fn get_tee_key() -> String {
        format!("{}/tee.key", Self::get_work_dir())
    }

    fn get_attestation_token() -> String {
        format!("{}/attestation_token", Self::get_work_dir())
    }

    fn get_kbs_client_path() -> String {
        format!(
            "{}/confidential-containers/trustee/target/release/kbs-client",
            Self::SNP_VM_CODE_DIR
        )
    }

    fn get_kbs_url() -> String {
        env::var("TLESS_KBS_URL").unwrap()
    }

    async fn set_resource_policy() -> Result<()> {
        let tee_policy_rego = format!(
            r#"
package policy
default allow = false
allow {{
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["{}"]
}}
"#,
            Self::TEE
        );

        let tmp_file = "/tmp/tee_policy.rego";
        fs::write(tmp_file, &tee_policy_rego)?;

        Command::new("sudo")
            .args([
                "-E",
                &Self::get_kbs_client_path(),
                "--url",
                &Self::get_kbs_url(),
                "--cert-file",
                &Self::get_https_cert(),
                "config",
                "--auth-private-key",
                &Self::get_kbs_key(),
                "set-resource-policy",
                "--policy-file",
                tmp_file,
            ])
            .output()?;

        Ok(())
    }

    async fn generate_attestation_token() -> Result<()> {
        let output = Command::new("sudo")
            .args([
                "-E",
                &Self::get_kbs_client_path(),
                "--url",
                &Self::get_kbs_url(),
                "--cert-file",
                &Self::get_https_cert(),
                "attest",
                "--tee-key-file",
                &Self::get_tee_key(),
            ])
            .output()?;

        fs::write(&Self::get_attestation_token(), output.stdout)?;

        Ok(())
    }

    pub async fn get_trustee_resource() -> Result<()> {
        Command::new("sudo")
            .args([
                "-E",
                &Self::get_kbs_client_path(),
                "--url",
                &Self::get_kbs_url(),
                "--cert-file",
                &Self::get_https_cert(),
                "get-resource",
                // TODO: if we comment out these next two lines we are including
                // the attestation in the loop, which seems more realistic, but
                // i am running into some race conditions
                "--tee-key-file",
                &Self::get_tee_key(),
                "--attestation-token",
                &Self::get_attestation_token(),
                "--path",
                "one/two/three",
            ])
            .output()?;

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Managed HSM methods and constants
    // -------------------------------------------------------------------------

    /// The individual request to the managed HSM is to wrap a payload using
    /// the policy-protected key. To unlock the key we must provide a valid
    /// attestation token from MAA.
    pub async fn wrap_key_in_mhsm() -> Result<()> {
        let azure_attest_bin_path = format!(
            "{}/azure/confidential-computing-cvm-guest-attestation\
            /cvm-securekey-release-app/build",
            Self::SNP_VM_CODE_DIR
        );

        // This method is ran from the client SNP cVM in Azure, so we cannot
        // use create::Azure (i.e. `az`) to query for the resource URIs
        let az_attestation_uri = "https://tlessmhsm.eus.attest.azure.net";
        let az_kv_kid = "https://tless-mhsm-kv.vault.azure.net/keys/tless-mhsm-key";

        Command::new("sudo")
            .args([
                format!("{azure_attest_bin_path}/AzureAttestSKR").as_str(),
                "-a",
                az_attestation_uri,
                "-k",
                az_kv_kid,
                "-s",
                "foobar123",
                "-w",
            ])
            .output()?;

        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct UbenchRunArgs {
    #[arg(short, long, value_name = "BASELINE")]
    baseline: EscrowBaseline,
    #[arg(long, default_value = "3")]
    num_repeats: u32,
    #[arg(long, default_value = "0")]
    num_warmup_repeats: u32,
}

#[derive(Debug)]
pub struct Ubench {}

impl Ubench {
    fn get_progress_bar(
        num_repeats: u32,
        exp: &MicroBenchmarks,
        baseline: &str,
        mode: &str,
    ) -> ProgressBar {
        let pb = ProgressBar::new(num_repeats.into());
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
                .expect("invrs(eval): error creating progress bar")
                .progress_chars("#>-"),
        );
        pb.set_message(format!("{exp}/{baseline}/{mode}"));
        pb
    }

    fn run_edag_verify_ubench(run_args: &UbenchRunArgs) {
        let baselines: Vec<&str> = vec!["crypto-acc", "vanilla"];
        let mut verify_dir = Env::proj_root();
        verify_dir.push("verify");

        let modes = vec![0, 1];

        for baseline in &baselines {
            // Work-out binary path
            let mut binary_path = Env::proj_root();
            binary_path.push("verify");
            match *baseline {
                "crypto-acc" => binary_path.push("target/release/host"),
                "vanilla" => binary_path.push("target-nocrypto-acc/release/host"),
                _ => panic!("tlessctl(eval): unsupported baseline {baseline}"),
            };

            for mode in &modes {
                let mode_name = match *mode {
                    0 => "noagg",
                    1 => "agg",
                    _ => panic!("tless(eval): unrecognised mode"),
                };

                // Work-out file name
                let mut results_dir = Env::proj_root();
                results_dir.push("eval");
                results_dir.push(format!("{}", MicroBenchmarks::VerifyEDag));
                results_dir.push("data");
                fs::create_dir_all(results_dir.clone()).unwrap();
                results_dir.push(format!("{baseline}_{mode_name}.csv"));

                let mut csv_file = BufWriter::new(File::create(results_dir).unwrap());
                writeln!(csv_file, "Run,Parameter,ExecTimeMS").unwrap();

                let pb = Self::get_progress_bar(
                    MAX_NUM_CHAINS * run_args.num_repeats,
                    &MicroBenchmarks::VerifyEDag,
                    baseline,
                    mode_name,
                );
                for param in 1..=MAX_NUM_CHAINS {
                    for run in 1..=run_args.num_repeats {
                        let start = Instant::now();
                        // Execute the baseline binary with the mode and parameter
                        let output = Command::new(binary_path.clone())
                            .current_dir(verify_dir.clone())
                            .arg(mode.to_string())
                            .arg(param.to_string())
                            .output()
                            .unwrap();

                        // Ensure command executed successfully
                        match output.status.code() {
                            Some(0) => {
                                let elapsed_time = start.elapsed().as_millis();
                                writeln!(csv_file, "{},{},{:?}", run, param, elapsed_time).unwrap();
                                pb.inc(1);
                            }
                            _ => {
                                let stderr = str::from_utf8(&output.stderr)
                                    .unwrap_or("tlessctl(eval): failed to get stderr");
                                eprintln!("tlessctl(eval): error running command: {}", stderr);
                            }
                        }
                    }
                }

                pb.finish();
            }
        }
    }

    async fn measure_requests_latency(
        baseline: &EscrowBaseline,
        num_requests: usize,
    ) -> Result<f64> {
        // TODO: get rid of me
        println!(
            "Processing {} requests for baseline {baseline} with parallelism={}...",
            num_requests, REQUEST_PARALLELISM
        );

        let start = Instant::now();

        stream::iter(0..num_requests)
            .map(|_| match &baseline {
                EscrowBaseline::Trustee => tokio::spawn(EscrowBaseline::get_trustee_resource()),
                EscrowBaseline::ManagedHSM => tokio::spawn(EscrowBaseline::wrap_key_in_mhsm()),
                EscrowBaseline::Accless | EscrowBaseline::AcclessMaa => {
                    panic!("accless-based baselines must be run from different script")
                }
            })
            .buffer_unordered(REQUEST_PARALLELISM)
            .for_each(|res| async {
                if let Err(e) = res {
                    eprintln!(
                        "individual secret release request failed: {:?} (baseline: {baseline})",
                        e
                    );
                }
            })
            .await;

        let time_elapsed = start.elapsed().as_secs_f64();
        println!("Time elapsed: {}s", time_elapsed);
        Ok(time_elapsed)
    }

    async fn run_escrow_ubench(run_args: &UbenchRunArgs) -> Result<()> {
        let results_file = Env::proj_root()
            .join("eval")
            .join(format!("{}", MicroBenchmarks::EscrowXput))
            .join("data")
            .join(format!("{}.csv", run_args.baseline));

        let mut csv_file = BufWriter::new(File::create(results_file).unwrap());
        writeln!(csv_file, "NumRequests,TimeElapsed").unwrap();

        if run_args.baseline == EscrowBaseline::Trustee {
            EscrowBaseline::set_resource_policy().await?;
            // TODO: ideally we would generate the attestation token with
            // each new request but, unfortunately, there seems to be some
            // race condition in the vTPM source code that prevents getting
            // many HW attesation reports concurrently.
            EscrowBaseline::generate_attestation_token().await?;
        }

        let request_counts = match run_args.baseline {
            EscrowBaseline::Trustee => REQUEST_COUNTS_TRUSTEE,
            EscrowBaseline::ManagedHSM => REQUEST_COUNTS_MHSM,
            EscrowBaseline::Accless | EscrowBaseline::AcclessMaa => {
                panic!("accless baselines must be run from different script")
            }
        };
        for &num_req in request_counts {
            for _ in 0..run_args.num_repeats {
                let elapsed_time =
                    Self::measure_requests_latency(&run_args.baseline, num_req).await?;
                println!("elapsed time: {elapsed_time}");
                writeln!(csv_file, "{},{:?}", num_req, elapsed_time)?;
            }
        }

        Ok(())
    }

    fn get_all_data_files(exp: &MicroBenchmarks) -> Vec<PathBuf> {
        let data_path = format!("{}/eval/{exp}/data", Env::proj_root().display());

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

    fn plot_escrow_xput_ubench(data_files: &Vec<PathBuf>) {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Record {
            #[allow(dead_code)]
            num_requests: usize,
            time_elapsed: f64,
        }

        // Collect data
        let mut data = BTreeMap::<EscrowBaseline, [f64; REQUEST_COUNTS_TRUSTEE.len()]>::new();
        for baseline in EscrowBaseline::iter_variants() {
            data.insert(baseline.clone(), [0.0; REQUEST_COUNTS_TRUSTEE.len()]);
        }

        for csv_file in data_files {
            let file_name = csv_file
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or_default();
            debug!("file name: {file_name}");

            let file_name_len = file_name.len();
            let baseline: EscrowBaseline = file_name[0..file_name_len - 4].parse().unwrap();

            // Open the CSV and deserialize records
            let mut reader = ReaderBuilder::new()
                .has_headers(true)
                .from_path(csv_file)
                .unwrap();
            let mut count = 0;

            for result in reader.deserialize() {
                debug!("{baseline}: {csv_file:?}");
                let record: Record = result.unwrap();

                let agg_times = data.get_mut(&baseline).unwrap();

                count += 1;
                let n_req = record.num_requests;
                let request_counts = match baseline {
                    EscrowBaseline::Trustee
                    | EscrowBaseline::Accless
                    | EscrowBaseline::AcclessMaa => REQUEST_COUNTS_TRUSTEE,
                    EscrowBaseline::ManagedHSM => REQUEST_COUNTS_MHSM,
                };
                let idx = request_counts
                    .iter()
                    .position(|&x| n_req == x)
                    .expect("num. requests not found!");
                agg_times[idx] += record.time_elapsed;
            }

            let num_repeats: f64 = (count / REQUEST_COUNTS_TRUSTEE.len()) as f64;

            let average_times = data.get_mut(&baseline).unwrap();
            for i in 0..average_times.len() {
                average_times[i] = average_times[i] / num_repeats;
            }
        }

        let mut plot_path = Env::proj_root();
        plot_path.push("eval");
        plot_path.push(format!("{}", MicroBenchmarks::EscrowXput));
        plot_path.push("plots");
        fs::create_dir_all(plot_path.clone()).unwrap();
        plot_path.push(format!("{}.svg", MicroBenchmarks::EscrowXput));

        // Plot data
        let root = SVGBackend::new(&plot_path, (800, 300)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        let x_max = 1000;
        let y_max: f64 = 20.0;
        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .margin_top(40)
            .margin_left(50)
            .margin_right(25)
            .margin_bottom(20)
            .build_cartesian_2d(0..x_max, 0f64..y_max as f64)
            .unwrap();

        chart
            .configure_mesh()
            // .disable_mesh()
            .light_line_style(&WHITE)
            .x_labels(8)
            .y_labels(6)
            .x_label_style(("sans-serif", FONT_SIZE).into_font())
            .y_label_style(("sans-serif", FONT_SIZE).into_font())
            .x_desc("")
            .draw()
            .unwrap();

        // Manually draw the X/Y-axis label with a custom font and size
        root.draw(&Text::new(
            "Latency [s]",
            (5, 200),
            ("sans-serif", FONT_SIZE)
                .into_font()
                .transform(FontTransform::Rotate270)
                .color(&BLACK),
        ))
        .unwrap();
        root.draw(&Text::new(
            "Throughput [RPS]",
            (350, 275),
            ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
        ))
        .unwrap();

        for (baseline, values) in data {
            // Draw line
            chart
                .draw_series(LineSeries::new(
                    (1..values.len())
                        .zip(values[1..].iter())
                        .filter(|(_, y)| **y <= y_max)
                        .map(|(x, y)| {
                            (
                                match baseline {
                                    EscrowBaseline::Trustee
                                    | EscrowBaseline::Accless
                                    | EscrowBaseline::AcclessMaa => {
                                        REQUEST_COUNTS_TRUSTEE[x] as i32
                                    }
                                    EscrowBaseline::ManagedHSM => REQUEST_COUNTS_MHSM[x] as i32,
                                },
                                *y,
                            )
                        }),
                    EscrowBaseline::get_color(&baseline).stroke_width(5),
                ))
                .unwrap();

            // Draw data point on line
            chart
                .draw_series(
                    (1..values.len())
                        .zip(values[1..].iter())
                        .filter(|(_, y)| **y <= y_max)
                        .map(|(x, y)| {
                            Circle::new(
                                (
                                    match baseline {
                                        EscrowBaseline::Trustee
                                        | EscrowBaseline::Accless
                                        | EscrowBaseline::AcclessMaa => {
                                            REQUEST_COUNTS_TRUSTEE[x] as i32
                                        }
                                        EscrowBaseline::ManagedHSM => REQUEST_COUNTS_MHSM[x] as i32,
                                    },
                                    *y,
                                ),
                                7,
                                EscrowBaseline::get_color(&baseline).filled(),
                            )
                        }),
                )
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

        fn legend_label_pos_for_baseline(baseline: &EscrowBaseline) -> (i32, i32) {
            let legend_x_start = 120;
            let legend_y_pos = 6;

            match baseline {
                EscrowBaseline::Trustee => (legend_x_start, legend_y_pos),
                EscrowBaseline::ManagedHSM => (legend_x_start + 120, legend_y_pos),
                EscrowBaseline::AcclessMaa => (legend_x_start + 320, legend_y_pos),
                EscrowBaseline::Accless => (legend_x_start + 490, legend_y_pos),
            }
        }

        // for id_x in 0..EscrowBaseline::iter_variants().len() {
        for baseline in EscrowBaseline::iter_variants() {
            // Calculate position for each legend item
            let (x_pos, y_pos) = legend_label_pos_for_baseline(&baseline);

            // Draw the color box (Rectangle) + frame
            let square_side = 20;
            root.draw(&Rectangle::new(
                [(x_pos, y_pos), (x_pos + square_side, y_pos + square_side)],
                EscrowBaseline::get_color(&baseline).filled(),
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
                format!("{baseline}"),
                (x_pos + 30, y_pos + 2), // Adjust text position
                ("sans-serif", FONT_SIZE).into_font(),
            ))
            .unwrap();
        }

        root.present().unwrap();
        println!("invrs: generated plot at: {}", plot_path.display());
    }

    fn plot_edag_verify_ubench(data_files: &Vec<PathBuf>) {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Record {
            #[allow(dead_code)]
            run: u32,
            parameter: u32,
            exec_time_m_s: u128,
        }

        // Use crypto-acceleration or not
        let baselines: Vec<&str> = vec!["crypto-acc", "vanilla"];
        // Aggreagate signatures or not
        let modes: Vec<&str> = vec!["agg", "noagg"];
        let agg_func_exec_time: i32 = 10 * 1000; // 10 seconds

        // one more than MAX_CHAINS
        const VEC_SIZE: usize = 11;

        // Collect data
        let mut data = BTreeMap::<&str, BTreeMap<&str, [u128; VEC_SIZE]>>::new();
        for baseline in &baselines {
            let mut inner_map = BTreeMap::<&str, [u128; VEC_SIZE]>::new();
            for mode in &modes {
                inner_map.insert(*mode, [0; VEC_SIZE]);
            }
            data.insert(*baseline, inner_map);
        }

        for (baseline, inner) in &data {
            for (mode, agg) in inner {
                println!("{baseline}/{mode}: size {}", agg.len());
            }
        }

        let mut y_max: f64 = 0.0;
        for csv_file in data_files {
            let file_name = csv_file
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or_default();
            let file_name_len = file_name.len();
            let file_name_no_ext = &file_name[0..file_name_len - 4];
            let parts: Vec<&str> = file_name_no_ext.split("_").collect();

            let baseline: &str = parts[0];
            let mode: &str = parts[1];

            // Open the CSV and deserialize records
            let mut reader = ReaderBuilder::new()
                .has_headers(true)
                .from_path(csv_file)
                .unwrap();
            let mut count = 0;

            for result in reader.deserialize() {
                println!("{baseline}/{mode}: {csv_file:?}");
                let record: Record = result.unwrap();

                let agg_times = data.get_mut(&baseline).unwrap().get_mut(&mode).unwrap();

                count += 1;
                let idx: usize = record.parameter.try_into().unwrap();
                agg_times[idx] += record.exec_time_m_s;
            }

            let num_repeats: u128 = (count / MAX_NUM_CHAINS).into();

            let average_times = data.get_mut(&baseline).unwrap().get_mut(&mode).unwrap();
            for i in 0..average_times.len() {
                average_times[i] = average_times[i] / num_repeats;

                // For signature aggregation baselines, add the expected runtime
                // of the signature aggregation function
                if mode == "agg" {
                    average_times[i] += agg_func_exec_time as u128;
                }

                let y_val: f64 = (average_times[i] / 1000) as f64;
                if y_val > y_max {
                    y_max = y_val;
                }
            }
        }

        let mut plot_path = Env::proj_root();
        plot_path.push("eval");
        plot_path.push(format!("{}", MicroBenchmarks::VerifyEDag));
        plot_path.push("plots");
        fs::create_dir_all(plot_path.clone()).unwrap();
        plot_path.push(format!("{}.svg", MicroBenchmarks::VerifyEDag));

        // Plot data
        let root = SVGBackend::new(&plot_path, (800, 300)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .margin_top(40)
            .margin_left(40)
            .build_cartesian_2d(0..10, 0f64..y_max as f64)
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
            "# of leaves in eDag",
            (400, 280),
            ("sans-serif", 20).into_font().color(&BLACK),
        ))
        .unwrap();

        fn get_color_for_baseline(label: &str, mode: &str) -> RGBColor {
            match format!("{label}_{mode}").as_str() {
                "crypto-acc_agg" => RGBColor(171, 222, 230),
                "crypto-acc_noagg" => RGBColor(203, 170, 203),
                "vanilla_agg" => RGBColor(255, 204, 182),
                "vanilla_noagg" => RGBColor(243, 176, 195),
                _ => panic!("tlessctl: unrecognized combination: {label}, {mode}"),
            }
        }

        fn get_text_for_baseline(label: &str, mode: &str) -> String {
            match format!("{label}_{mode}").as_str() {
                "crypto-acc_agg" => "tless verify".to_string(),
                "crypto-acc_noagg" => "baseline + crypto".to_string(),
                "vanilla_agg" => "baseline + sig. agg".to_string(),
                "vanilla_noagg" => "baseline".to_string(),
                _ => panic!("tlessctl: unrecognized combination: {label}, {mode}"),
            }
        }

        for (label, inner_data) in data {
            for (mode, values) in inner_data {
                chart
                    .draw_series(LineSeries::new(
                        (1..values.len())
                            .zip(values[1..].iter())
                            .map(|(x, y)| (x as i32, *y as f64 / 1000.0)),
                        get_color_for_baseline(label, mode).stroke_width(3),
                    ))
                    .unwrap();

                chart
                    .draw_series((1..values.len()).zip(values[1..].iter()).map(|(x, y)| {
                        Circle::new(
                            (x as i32, *y as f64 / 1000.0),
                            5,
                            get_color_for_baseline(label, mode).filled(),
                        )
                    }))
                    .unwrap();
            }
        }

        fn legend_label_pos_for_baseline(label: &str, mode: &str) -> (i32, i32) {
            let legend_x_start = 100;
            let legend_y_pos = 6;

            match format!("{label}_{mode}").as_str() {
                "crypto-acc_agg" => (legend_x_start, legend_y_pos),
                "crypto-acc_noagg" => (legend_x_start + 150, legend_y_pos),
                "vanilla_agg" => (legend_x_start + 350, legend_y_pos),
                "vanilla_noagg" => (legend_x_start + 550, legend_y_pos),
                _ => panic!("tlessctl: unrecognized combination: {label}, {mode}"),
            }
        }

        for id_x in 0..baselines.len() {
            for id_y in 0..modes.len() {
                // Calculate position for each legend item
                let (x_pos, y_pos) = legend_label_pos_for_baseline(baselines[id_x], modes[id_y]);

                // Draw the color box (Rectangle)
                root.draw(&Rectangle::new(
                    [(x_pos, y_pos), (x_pos + 20, y_pos + 20)],
                    get_color_for_baseline(baselines[id_x], modes[id_y]).filled(),
                ))
                .unwrap();

                // Draw the baseline label (Text)
                root.draw(&Text::new(
                    get_text_for_baseline(baselines[id_x], modes[id_y]),
                    (x_pos + 30, y_pos - 4), // Adjust text position
                    ("sans-serif", 20).into_font(),
                ))
                .unwrap();
            }
        }

        root.present().unwrap();
    }

    pub async fn run(ubench: &MicroBenchmarks, run_args: &UbenchRunArgs) {
        match ubench {
            MicroBenchmarks::EscrowXput => Self::run_escrow_ubench(&run_args).await.unwrap(),
            MicroBenchmarks::VerifyEDag => Self::run_edag_verify_ubench(&run_args),
        }
    }

    pub fn plot(ubench: &MicroBenchmarks) {
        let data_files = Self::get_all_data_files(ubench);

        match ubench {
            MicroBenchmarks::EscrowXput => Self::plot_escrow_xput_ubench(&data_files),
            MicroBenchmarks::VerifyEDag => Self::plot_edag_verify_ubench(&data_files),
        };
    }
}

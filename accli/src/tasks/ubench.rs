use crate::{
    env::Env,
    tasks::color::{FONT_SIZE, STROKE_WIDTH, get_color_from_label},
};
use anyhow::Result;
use clap::{Args, ValueEnum};
use csv::ReaderBuilder;
use futures::stream::{self, StreamExt};
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

// We obtain this numbers by following the instructions to run the escrow-xput
// benchmark, and do a run where we modify the number of requests to be [0, 10]
// These numbers are run when the server is a D2
const ACCLESS_LATENCY_D2: &[f64] = &[
    0.091594, 0.100394, 0.107495, 0.111224, 0.11829, 0.122359, 0.126534, 0.131722, 0.127414,
    0.123334,
];
// Rounded monthly cost (in USD) of a Standard_DCas_v5 as of 17/04/2025
const UNIT_MONTHLY_COST_DC2: u32 = 62;

const REQUEST_COUNTS_MHSM: &[usize] = &[1, 5, 10, 15, 20, 40, 60, 80, 100];
const REQUEST_COUNTS_TRUSTEE: &[usize] = &[1, 20, 60, 80, 100, 120, 160, 180, 200];
const REQUEST_PARALLELISM: usize = 10;

pub enum MicroBenchmarks {
    EscrowCost,
    EscrowXput,
}

impl fmt::Display for MicroBenchmarks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MicroBenchmarks::EscrowCost => write!(f, "escrow-cost"),
            MicroBenchmarks::EscrowXput => write!(f, "escrow-xput"),
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

        fs::write(Self::get_attestation_token(), output.stdout)?;

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

        csv_files
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
            for time in average_times {
                *time /= num_repeats;
            }
        }

        let mut plot_path = Env::proj_root();
        plot_path.push("eval");
        plot_path.push(format!("{}", MicroBenchmarks::EscrowXput));
        plot_path.push("plots");
        fs::create_dir_all(plot_path.clone()).unwrap();
        plot_path.push(format!("{}.svg", MicroBenchmarks::EscrowXput));

        // Plot data
        let root = SVGBackend::new(&plot_path, (400, 300)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        let x_max = 200;
        let y_max: f64 = 5.0;
        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .margin_top(40)
            .margin_left(50)
            .margin_right(25)
            .margin_bottom(20)
            .build_cartesian_2d(0..x_max, 0f64..y_max)
            .unwrap();

        chart
            .configure_mesh()
            .light_line_style(WHITE)
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
            (125, 275),
            ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
        ))
        .unwrap();

        for (baseline, values) in data {
            // Draw line
            chart
                .draw_series(LineSeries::new(
                    (0..values.len())
                        .zip(values[0..].iter())
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
                    EscrowBaseline::get_color(&baseline).stroke_width(STROKE_WIDTH),
                ))
                .unwrap();

            // Draw data point on line
            chart
                .draw_series(
                    (0..values.len())
                        .zip(values[0..].iter())
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
                                5,
                                EscrowBaseline::get_color(&baseline).filled(),
                            )
                        }),
                )
                .unwrap();
        }

        // Add solid frames
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(0, y_max), (x_max, y_max)], BLACK))
            .unwrap();
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(x_max, 0.0), (x_max, y_max)], BLACK))
            .unwrap();

        fn legend_label_pos_for_baseline(baseline: &EscrowBaseline) -> (i32, i32) {
            let legend_x_start = 20;
            let legend_y_pos = 6;

            match baseline {
                EscrowBaseline::ManagedHSM => (legend_x_start, legend_y_pos),
                EscrowBaseline::AcclessMaa => (legend_x_start + 220, legend_y_pos),
                _ => panic!(),
            }
        }

        // NOTE: we combine the labels with the figure that is placed side-by-side
        for baseline in [EscrowBaseline::ManagedHSM, EscrowBaseline::AcclessMaa] {
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
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos + 20, y_pos), (x_pos + 20, y_pos + 20)],
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos), (x_pos, y_pos + 20)],
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos + 20), (x_pos + 20, y_pos + 20)],
                BLACK,
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

    fn plot_escrow_cost() {
        // Variables:
        let trustee_latency_single_req = 0.05;
        let trustee_unit_cost = UNIT_MONTHLY_COST_DC2;
        let accless_unit_cost = UNIT_MONTHLY_COST_DC2;
        let num_max_users = 10;
        let accless_latency: Vec<(u32, f64)> = (1..=ACCLESS_LATENCY_D2.len() as u32)
            .map(|x| (x, ACCLESS_LATENCY_D2[x as usize - 1]))
            .collect();

        let plot_path = Env::proj_root()
            .join("eval")
            .join(format!("{}", MicroBenchmarks::EscrowCost))
            .join("plots")
            .join("cost.svg");
        let root = SVGBackend::new(&plot_path, (400, 300)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        let mut chart = ChartBuilder::on(&root)
            .margin(10)
            .margin_top(40)
            .margin_left(40)
            .margin_bottom(20)
            .margin_right(45)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .right_y_label_area_size(40)
            .build_cartesian_2d(1u32..num_max_users, 0.0f64..300.0)
            .unwrap()
            .set_secondary_coord(
                1u32..num_max_users,
                0f64..(num_max_users * trustee_unit_cost) as f64,
            ); // Right axis for cost

        // Draw meshes
        chart
            .configure_mesh()
            .light_line_style(WHITE)
            .x_label_style(("sans-serif", FONT_SIZE).into_font())
            .x_labels(8)
            .y_labels(6)
            .y_label_formatter(&|y| format!("{:.0}", y))
            .y_label_style(("sans-serif", FONT_SIZE).into_font())
            .draw()
            .unwrap();

        chart
            .configure_secondary_axes()
            .label_style(("sans-serif", FONT_SIZE).into_font())
            .y_label_formatter(&|y| format!("{:.0}", y))
            .y_labels(6)
            .draw()
            .unwrap();

        // Manually draw the X/Y-axis label with a custom font and size
        root.draw(&Text::new(
            "Latency [ms]",
            (5, 215),
            ("sans-serif", FONT_SIZE)
                .into_font()
                .transform(FontTransform::Rotate270)
                .color(&BLACK),
        ))
        .unwrap();
        root.draw(&Text::new(
            "# of users ",
            (120, 280),
            ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
        ))
        .unwrap();
        root.draw(&Text::new(
            "Op. Cost [$/month]",
            (390, 35),
            ("sans-serif", FONT_SIZE)
                .into_font()
                .transform(FontTransform::Rotate90)
                .color(&BLACK),
        ))
        .unwrap();

        chart
            .draw_series(LineSeries::new(
                (1..=num_max_users).map(|x| (x, trustee_latency_single_req * 1000.0)),
                EscrowBaseline::get_color(&EscrowBaseline::Trustee).stroke_width(STROKE_WIDTH),
            ))
            .unwrap();

        chart
            .draw_series(LineSeries::new(
                accless_latency
                    .clone()
                    .into_iter()
                    .map(|(x, y)| (x, y * 1000.0)),
                EscrowBaseline::get_color(&EscrowBaseline::Accless).stroke_width(STROKE_WIDTH),
            ))
            .unwrap();

        // Cost: Trustee (linear y = unit_cost * x)
        let trustee_cost: Vec<(u32, f64)> = (1..=num_max_users)
            .map(|x| (x, (trustee_unit_cost * x) as f64))
            .collect();
        let trustee_cost_style =
            EscrowBaseline::get_color(&EscrowBaseline::Trustee).stroke_width(STROKE_WIDTH);
        chart
            .draw_secondary_series(LineSeries::new(trustee_cost.clone(), trustee_cost_style))
            .unwrap();
        chart
            .draw_secondary_series(trustee_cost.into_iter().map(|(x, y)| {
                Circle::new(
                    (x, y),
                    7,
                    EscrowBaseline::get_color(&EscrowBaseline::Trustee).filled(),
                )
            }))
            .unwrap();

        // Accless cost
        let accless_cost: Vec<(u32, f64)> = (1..=num_max_users)
            .map(|x| (x, (accless_unit_cost) as f64))
            .collect();
        chart
            .draw_secondary_series(LineSeries::new(
                accless_cost.clone(),
                EscrowBaseline::get_color(&EscrowBaseline::Accless).stroke_width(STROKE_WIDTH),
            ))
            .unwrap();
        chart
            .draw_secondary_series(accless_cost.into_iter().map(|(x, y)| {
                Circle::new(
                    (x, y),
                    7,
                    EscrowBaseline::get_color(&EscrowBaseline::Accless).filled(),
                )
            }))
            .unwrap();

        chart
            .plotting_area()
            .draw(&PathElement::new(
                vec![(0, 1.0), (num_max_users, 1.0)],
                BLACK,
            ))
            .unwrap();
        chart
            .plotting_area()
            .draw(&PathElement::new(
                vec![(num_max_users, 0.0), (num_max_users, 1.0)],
                BLACK,
            ))
            .unwrap();

        fn legend_label_pos_for_baseline(baseline: &EscrowBaseline) -> (i32, i32) {
            let legend_x_start = 100;
            let legend_y_pos = 6;

            match baseline {
                EscrowBaseline::Trustee => (legend_x_start, legend_y_pos),
                EscrowBaseline::Accless => (legend_x_start + 120, legend_y_pos),
                _ => panic!(),
            }
        }

        for baseline in &[EscrowBaseline::Trustee, EscrowBaseline::Accless] {
            // Calculate position for each legend item
            let (x_pos, y_pos) = legend_label_pos_for_baseline(baseline);

            // Draw the color box (Rectangle)
            root.draw(&Rectangle::new(
                [(x_pos, y_pos), (x_pos + 20, y_pos + 20)],
                baseline.get_color().filled(),
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![
                    (x_pos, y_pos),
                    (x_pos + 20, y_pos),
                    (x_pos + 20, y_pos + 20),
                    (x_pos, y_pos + 20),
                    (x_pos, y_pos),
                ],
                BLACK,
            ))
            .unwrap();

            // Draw the baseline label (Text)
            root.draw(&Text::new(
                format!("{baseline}"),
                (x_pos + 30, y_pos + 5),
                ("sans-serif", FONT_SIZE).into_font(),
            ))
            .unwrap();
        }

        root.present().unwrap();
        println!("invrs: generated plot at: {}", plot_path.display());
    }

    pub async fn run(ubench: &MicroBenchmarks, run_args: &UbenchRunArgs) {
        match ubench {
            MicroBenchmarks::EscrowCost => panic!("escrow-cost is not meant to be ran"),
            MicroBenchmarks::EscrowXput => Self::run_escrow_ubench(run_args).await.unwrap(),
        }
    }

    pub fn plot(ubench: &MicroBenchmarks) {
        match ubench {
            MicroBenchmarks::EscrowXput => {
                let data_files = Self::get_all_data_files(ubench);
                Self::plot_escrow_xput_ubench(&data_files);
            }
            MicroBenchmarks::EscrowCost => Self::plot_escrow_cost(),
        };
    }
}

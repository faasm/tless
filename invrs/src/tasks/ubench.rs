use clap::Args;
use crate::env::Env;
use std::{fmt, fs::File, io::{Write, BufWriter}, process::Command, time::Instant};

pub enum MicroBenchmarks {
    VerifyEDag,
}

impl fmt::Display for MicroBenchmarks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MicroBenchmarks::VerifyEDag => write!(f, "verify-edag"),
        }
    }
}

#[derive(Debug, Args)]
pub struct UbenchRunArgs {
    // TODO: bump to 3
    #[arg(long, default_value = "1")]
    num_repeats: u32,
    #[arg(long, default_value = "0")]
    num_warmup_repeats: u32,
}

#[derive(Debug)]
pub struct Ubench {}

impl Ubench {
    fn run_edag_verify_ubench(run_args: &UbenchRunArgs) {
        let mut target_dir = Env::proj_root();
        target_dir.push("verify")

        let baselines = vec![
            "path/to/baseline2", // Second baseline
        ];

        let modes = vec![0, 1];
        // TODO: bump to 10
        let max_num_chains = 3;

        let mut csv_file = BufWriter::new(File::create("benchmark_results.csv").unwrap());
        writeln!(csv_file, "Run,Parameter,ExecTimeMS").unwrap();

        for baseline in &baselines {
            for mode in &modes {
                for param in 1..=max_num_chains {
                    for run in 1..=run_args.num_repeats {
                        let start = Instant::now();
                        // Execute the baseline binary with the mode and parameter
                        let output = Command::new(baseline)
                            .arg(mode.to_string())
                            .arg(param.to_string())
                            .output();

                        // Ensure command executed successfully
                        match output {
                            Ok(_) => {
                                let elapsed_time = start.elapsed().as_millis();
                                writeln!(csv_file, "{},{},{:?}", run, param, elapsed_time).unwrap();
                                println!(
                                    "Baseline: {}, Mode: {}, Param: {}, Run: {}, Time: {:?} ms",
                                    baseline, mode, param, run, elapsed_time
                                );
                            }
                            Err(e) => {
                                eprintln!("tlessctl(eval): error running command: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }

    fn plot_edag_verify_ubench() {
        println!("plot");
    }

    pub fn run(ubench: &MicroBenchmarks, run_args: UbenchRunArgs) {
        match ubench {
            MicroBenchmarks::VerifyEDag => Self::run_edag_verify_ubench(&run_args),
        };
    }

    pub fn plot(ubench: &MicroBenchmarks) {
        match ubench {
            MicroBenchmarks::VerifyEDag => Self::plot_edag_verify_ubench(),
        };
    }
}

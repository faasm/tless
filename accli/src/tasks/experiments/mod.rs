use crate::tasks::experiments::{e2e::E2eRunArgs, ubench::UbenchRunArgs};
use clap::Subcommand;
use std::fmt;

pub mod baselines;
pub mod color;
pub mod e2e;
pub mod plot;
pub mod ubench;
pub mod workflows;

/// Useful constants shared between the provisioning methods, and the
/// experiments methods.
pub const ACCLESS_MAA_NAME: &str = "accless";
pub const ACCLESS_VM_CODE_DIR: &str = "git/faasm/accless";
pub const ACCLESS_VM_NAME: &str = "accless-cvm";
pub const ACCLESS_ATTESTATION_SERVICE_VM_NAME: &str = "accless-as";
pub const ATTESTATION_SERVICE_VM_NAME: &str = "attestation-service";
pub const TRUSTEE_CLIENT_VM_NAME: &str = "accless-trustee-client";
pub const TRUSTEE_SERVER_VM_NAME: &str = "accless-trustee-server";

/// Supported experiments in Accless. For a detailed explanation of each of
/// them, refer to `./experiments/README.md`.
#[derive(Debug, Subcommand)]
pub enum Experiment {
    /// Measure the CDF of cold-starts with or w/out our access control
    ColdStart {
        #[command(subcommand)]
        eval_sub_command: E2eSubScommand,
    },
    /// Evaluate end-to-end execution latency for different workflows
    E2eLatency {
        #[command(subcommand)]
        eval_sub_command: E2eSubScommand,
    },
    /// Evaluate end-to-end execution latency (cold) for different workflows
    E2eLatencyCold {
        #[command(subcommand)]
        eval_sub_command: E2eSubScommand,
    },
    /// Measure the cost per user of different configurations
    EscrowCost {
        #[command(subcommand)]
        ubench_sub_command: UbenchSubCommand,
    },
    /// Measure the throughput of the trusted escrow as we increase the number
    /// of parallel authorization requests
    EscrowXput {
        #[command(subcommand)]
        ubench_sub_command: UbenchSubCommand,
    },
    /// Evaluate the latency when scaling-up the number of functions in the
    /// workflow
    ScaleUpLatency {
        #[command(subcommand)]
        eval_sub_command: E2eSubScommand,
    },
}

impl Experiment {
    pub const COLD_START_NAME: &'static str = "cold-start";
    pub const E2E_LATENCY_NAME: &'static str = "e2e-latency";
    pub const E2E_LATENCY_COLD_NAME: &'static str = "e2e-latency-cold";
    pub const ESCROW_COST_NAME: &'static str = "escrow-cost";
    pub const ESCROW_XPUT_NAME: &'static str = "escrow-xput";
    pub const SCALE_UP_LATENCY_NAME: &'static str = "scale-up-latency";

    pub fn name(&self) -> &'static str {
        match self {
            Experiment::ColdStart { .. } => "cold-start",
            Experiment::E2eLatency { .. } => "e2e-latency",
            Experiment::E2eLatencyCold { .. } => "e2e-latency-cold",
            Experiment::EscrowCost { .. } => "escrow-cost",
            Experiment::EscrowXput { .. } => "escrow-xput",
            Experiment::ScaleUpLatency { .. } => "scale-up-latency",
        }
    }
}

impl fmt::Display for Experiment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Experiment::ColdStart { .. } => write!(f, "{}", Self::COLD_START_NAME),
            Experiment::E2eLatency { .. } => write!(f, "{}", Self::E2E_LATENCY_NAME),
            Experiment::E2eLatencyCold { .. } => write!(f, "{}", Self::E2E_LATENCY_COLD_NAME),
            Experiment::EscrowCost { .. } => write!(f, "{}", Self::ESCROW_COST_NAME),
            Experiment::EscrowXput { .. } => write!(f, "{}", Self::ESCROW_XPUT_NAME),
            Experiment::ScaleUpLatency { .. } => write!(f, "{}", Self::SCALE_UP_LATENCY_NAME),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum E2eSubScommand {
    /// Run
    Run(E2eRunArgs),
    /// Plot
    Plot {},
    UploadState {
        /// Whereas we are using S3 with 'faasm' or 'knative'
        system: String,
    },
    UploadWasm {},
}

#[derive(Debug, Subcommand)]
pub enum UbenchSubCommand {
    /// Run
    Run(UbenchRunArgs),
    /// Plot
    Plot {},
}

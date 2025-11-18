use crate::{
    env::Env,
    tasks::experiments::{Experiment, baselines::EscrowBaseline},
};
use anyhow::Result;
use clap::Args;
use futures::stream::{self, StreamExt};
use std::{
    env, fs,
    fs::File,
    io::{BufWriter, Write},
    process::Command,
    str,
    time::Instant,
};

pub const REQUEST_COUNTS_MHSM: &[usize] = &[1, 5, 10, 15, 20, 40, 60, 80, 100];
pub const REQUEST_COUNTS_TRUSTEE: &[usize] = &[1, 20, 60, 80, 100, 120, 160, 180, 200];
const REQUEST_PARALLELISM: usize = 10;

#[derive(Debug, Args)]
pub struct UbenchRunArgs {
    #[arg(short, long, value_name = "BASELINE")]
    baseline: EscrowBaseline,
    #[arg(long, default_value = "3")]
    num_repeats: u32,
    #[arg(long, default_value = "0")]
    num_warmup_repeats: u32,
}

// -------------------------------------------------------------------------
// Trustee methods and constants
// -------------------------------------------------------------------------

const TEE: &str = "azsnpvtpm";
const SNP_VM_CODE_DIR: &str = "/home/tless/git";

fn get_work_dir() -> String {
    format!(
        "{}/confidential-containers/trustee/kbs/test/work",
        SNP_VM_CODE_DIR
    )
}

fn get_https_cert() -> String {
    format!("{}/https.crt", get_work_dir())
}

fn get_kbs_key() -> String {
    format!("{}/kbs.key", get_work_dir())
}

fn get_tee_key() -> String {
    format!("{}/tee.key", get_work_dir())
}

fn get_attestation_token() -> String {
    format!("{}/attestation_token", get_work_dir())
}

fn get_kbs_client_path() -> String {
    format!(
        "{}/confidential-containers/trustee/target/release/kbs-client",
        SNP_VM_CODE_DIR
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
        TEE
    );

    let tmp_file = "/tmp/tee_policy.rego";
    fs::write(tmp_file, &tee_policy_rego)?;

    Command::new("sudo")
        .args([
            "-E",
            &get_kbs_client_path(),
            "--url",
            &get_kbs_url(),
            "--cert-file",
            &get_https_cert(),
            "config",
            "--auth-private-key",
            &get_kbs_key(),
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
            &get_kbs_client_path(),
            "--url",
            &get_kbs_url(),
            "--cert-file",
            &get_https_cert(),
            "attest",
            "--tee-key-file",
            &get_tee_key(),
        ])
        .output()?;

    fs::write(get_attestation_token(), output.stdout)?;

    Ok(())
}

pub async fn get_trustee_resource() -> Result<()> {
    Command::new("sudo")
        .args([
            "-E",
            &get_kbs_client_path(),
            "--url",
            &get_kbs_url(),
            "--cert-file",
            &get_https_cert(),
            "get-resource",
            // TODO: if we comment out these next two lines we are including
            // the attestation in the loop, which seems more realistic, but
            // i am running into some race conditions
            "--tee-key-file",
            &get_tee_key(),
            "--attestation-token",
            &get_attestation_token(),
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
        SNP_VM_CODE_DIR
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

async fn measure_requests_latency(baseline: &EscrowBaseline, num_requests: usize) -> Result<f64> {
    // TODO: get rid of me
    println!(
        "Processing {} requests for baseline {baseline} with parallelism={}...",
        num_requests, REQUEST_PARALLELISM
    );

    let start = Instant::now();

    stream::iter(0..num_requests)
        .map(|_| match &baseline {
            EscrowBaseline::Trustee => tokio::spawn(get_trustee_resource()),
            EscrowBaseline::ManagedHSM => tokio::spawn(wrap_key_in_mhsm()),
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
    let results_file = Env::experiments_root()
        .join(Experiment::ESCROW_XPUT_NAME)
        .join("data")
        .join(format!("{}.csv", run_args.baseline));

    let mut csv_file = BufWriter::new(File::create(results_file).unwrap());
    writeln!(csv_file, "NumRequests,TimeElapsed").unwrap();

    if run_args.baseline == EscrowBaseline::Trustee {
        set_resource_policy().await?;
        // TODO: ideally we would generate the attestation token with
        // each new request but, unfortunately, there seems to be some
        // race condition in the vTPM source code that prevents getting
        // many HW attesation reports concurrently.
        generate_attestation_token().await?;
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
            let elapsed_time = measure_requests_latency(&run_args.baseline, num_req).await?;
            println!("elapsed time: {elapsed_time}");
            writeln!(csv_file, "{},{:?}", num_req, elapsed_time)?;
        }
    }

    Ok(())
}

pub async fn run(ubench: &Experiment, run_args: &UbenchRunArgs) -> Result<()> {
    match ubench {
        Experiment::EscrowCost { .. } => anyhow::bail!("escrow-cost is not meant to be ran"),
        Experiment::EscrowXput { .. } => run_escrow_ubench(run_args).await,
        _ => anyhow::bail!("experiment not a micro-benchmark (experiment={ubench:?})"),
    }
}

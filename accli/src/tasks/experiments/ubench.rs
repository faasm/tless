use crate::{
    env::Env,
    tasks::{
        applications::{ApplicationName, ApplicationType, Applications},
        azure::Azure,
        cvm,
        experiments::{self, Experiment, baselines::EscrowBaseline},
    },
};
use anyhow::Result;
use clap::Args;
use futures::stream::{self, StreamExt};
use log::error;
use std::{
    fs,
    fs::File,
    io::{BufWriter, Write},
    process::Command,
    str,
    time::Instant,
};

pub const REQUEST_COUNTS_MHSM: &[usize] = &[1, 5, 10, 15, 20, 40, 60, 80, 100];
pub const REQUEST_COUNTS_TRUSTEE: &[usize] = &[1, 20, 60, 80, 100, 120, 160, 180, 200];
pub const REQUEST_COUNTS_ACCLESS: &[usize] = REQUEST_COUNTS_TRUSTEE;
const REQUEST_PARALLELISM: usize = 10;

#[derive(Debug, Args)]
pub struct UbenchRunArgs {
    #[arg(short, long, value_name = "BASELINE")]
    baseline: EscrowBaseline,
    #[arg(long)]
    escrow_url: Option<String>,
    #[arg(long, default_value = "3")]
    num_repeats: u32,
    #[arg(long, default_value = "1")]
    num_warmup_repeats: u32,
}

// -------------------------------------------------------------------------
// Accless helper methods
// -------------------------------------------------------------------------

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

async fn set_resource_policy(escrow_url: &str) -> Result<()> {
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
            escrow_url,
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

async fn generate_attestation_token(escrow_url: &str) -> Result<()> {
    let output = Command::new("sudo")
        .args([
            "-E",
            &get_kbs_client_path(),
            "--url",
            escrow_url,
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

pub async fn get_trustee_resource(escrow_url: String) -> Result<()> {
    Command::new("sudo")
        .args([
            "-E",
            &get_kbs_client_path(),
            "--url",
            &escrow_url,
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

async fn measure_requests_latency(
    baseline: &EscrowBaseline,
    escrow_url: &str,
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
            EscrowBaseline::Trustee => {
                let owned_escrow_url = escrow_url.to_string();
                tokio::spawn(get_trustee_resource(owned_escrow_url))
            }
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

async fn run_escrow_ubench(escrow_url: &str, run_args: &UbenchRunArgs) -> Result<()> {
    let results_file = Env::experiments_root()
        .join(Experiment::ESCROW_XPUT_NAME)
        .join("data")
        .join(format!("{}.csv", run_args.baseline));
    if let Some(results_dir) = results_file.parent() {
        fs::create_dir_all(results_dir)?;
    }

    let mut csv_file = BufWriter::new(File::create(&results_file).unwrap());
    writeln!(csv_file, "NumRequests,TimeElapsed").unwrap();

    if run_args.baseline == EscrowBaseline::Trustee {
        set_resource_policy(escrow_url).await?;
        // TODO: ideally we would generate the attestation token with
        // each new request but, unfortunately, there seems to be some
        // race condition in the vTPM source code that prevents getting
        // many HW attesation reports concurrently.
        generate_attestation_token(escrow_url).await?;
    }

    let request_counts = match run_args.baseline {
        EscrowBaseline::Trustee => REQUEST_COUNTS_TRUSTEE,
        EscrowBaseline::ManagedHSM => REQUEST_COUNTS_MHSM,
        EscrowBaseline::Accless | EscrowBaseline::AcclessMaa => REQUEST_COUNTS_ACCLESS,
    };

    match run_args.baseline {
        // The Trustee and managed HSM baselines run the logic embedded in this file.
        EscrowBaseline::Trustee | EscrowBaseline::ManagedHSM => {
            for &num_req in request_counts {
                for _ in 0..run_args.num_repeats {
                    let elapsed_time =
                        measure_requests_latency(&run_args.baseline, escrow_url, num_req).await?;
                    println!("elapsed time: {elapsed_time}");
                    writeln!(csv_file, "{},{:?}", num_req, elapsed_time)?;
                }
            }
        }
        // The Accless baselines run a function that performs SKR and CP-ABE keygen.
        EscrowBaseline::Accless | EscrowBaseline::AcclessMaa => {
            // This path is hard-coded during the Ansible provisioning of the
            // attestation-service.
            let cert_path = Env::proj_root()
                .join("config")
                .join("attestation-service")
                .join("certs")
                .join("az_cert.pem");
            let num_reqs = request_counts
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",");

            Applications::run(
                ApplicationType::Function,
                ApplicationName::EscrowXput,
                // FIXME(#56): for the time being, we pass --in-cvm. Once we support validating az
                // cVM quotes we can get rid of this.
                true,
                Some(format!("https://{escrow_url}:8443")),
                Some(cert_path),
                vec![
                    "--num-warmup-repeats".to_string(),
                    run_args.num_warmup_repeats.to_string(),
                    "--num-repeats".to_string(),
                    run_args.num_repeats.to_string(),
                    "--num-requests".to_string(),
                    num_reqs,
                ],
            )?;

            // SCP results from the cVM to local filesystem.
            cvm::scp("cvm:accless.csv", &results_file.display().to_string())?;
        }
    }

    Ok(())
}

/// Entrypoint function to run the micro-benchmark experiments.
///
/// These micro-benchmarks must be ran on remote machines, but we orchestrate
/// their execution from our local CLI, so we differentiate between invocation
/// inside an Azure VM or not.
pub async fn run(ubench: &Experiment, run_args: &UbenchRunArgs) -> Result<()> {
    let in_azure = Azure::is_azure_vm().await;

    if !in_azure {
        match run_args.baseline {
            EscrowBaseline::Trustee => {
                let cmd_in_vm = vec![
                    "./scripts/accli_wrapper.sh".to_string(),
                    "experiments".to_string(),
                    "escrow-xput".to_string(),
                    "run".to_string(),
                    "--baseline".to_string(),
                    "trustee".to_string(),
                    "--escrow-url".to_string(),
                    Azure::get_vm_ip(experiments::TRUSTEE_SERVER_VM_NAME)?,
                    "--num-repeats".to_string(),
                    run_args.num_repeats.to_string(),
                    "--num-warmup-repeats".to_string(),
                    run_args.num_warmup_repeats.to_string(),
                ];
                Azure::run_cmd_in_vm(experiments::TRUSTEE_CLIENT_VM_NAME, &cmd_in_vm)?;

                // TODO: scp results

                return Ok(());
            }
            // FIXME(#55): for the time being, we run Accless baselines locally, not in an
            // azure cVM.
            EscrowBaseline::Accless | EscrowBaseline::AcclessMaa => {}
            _ => todo!(),
        }
    }

    // Get the escrow URL from the ansible deployment.
    let escrow_url = match run_args.baseline {
        EscrowBaseline::Trustee | EscrowBaseline::ManagedHSM => {
            if run_args.escrow_url.is_none() {
                let reason = "running baseline in azure VM but no escrow URL provided";
                error!("run(): {reason}");
                anyhow::bail!(reason);
            }
            run_args.escrow_url.clone().unwrap()
        }
        EscrowBaseline::Accless | EscrowBaseline::AcclessMaa => {
            Azure::get_vm_ip(experiments::ACCLESS_ATTESTATION_SERVICE_VM_NAME)?
        }
    };

    match ubench {
        Experiment::EscrowCost { .. } => anyhow::bail!("escrow-cost is not meant to be ran"),
        Experiment::EscrowXput { .. } => run_escrow_ubench(&escrow_url, run_args).await,
        _ => anyhow::bail!("experiment not a micro-benchmark (experiment={ubench:?})"),
    }
}

use crate::{
    env::Env,
    tasks::{
        applications::{
            ApplicationBackend, ApplicationName, ApplicationType, Applications,
            host_cert_dir_to_target_path,
        },
        azure::{self, Azure},
        docker::Docker,
        experiments::{self, Experiment, baselines::EscrowBaseline},
    },
};
use anyhow::Result;
use az_snp_vtpm::{hcl::HclReport, report::AttestationReport, vtpm};
use base64::Engine;
use clap::Args;
use futures::stream::{self, StreamExt};
use log::error;
use std::{
    collections::HashMap,
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

const TEE: &str = "az-snp-vtpm";

fn get_coco_code_dir() -> String {
    format!(
        "/home/{}/git/confidential-containers",
        azure::AZURE_USERNAME
    )
}

fn get_work_dir() -> String {
    format!("{}/trustee/kbs/test/work", get_coco_code_dir())
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
    format!("{}/trustee/target/release/kbs-client", get_coco_code_dir())
}

async fn set_reference_values(escrow_url: &str) -> Result<()> {
    let report = vtpm::get_report()?;
    let quote = vtpm::get_quote(&[])?;
    let hcl_report = HclReport::new(report.clone())?;
    let snp_report: AttestationReport = hcl_report.try_into()?;

    let reference_values: HashMap<&str, String> = HashMap::from([
        (
            "measurement",
            base64::engine::general_purpose::STANDARD.encode(snp_report.report_data),
        ),
        (
            "snp_pcr11",
            hex::encode(quote.pcrs_sha256().nth(11).unwrap()),
        ),
        (
            "tcb_bootloader",
            snp_report.reported_tcb.bootloader.to_string(),
        ),
        (
            "tcb_microcode",
            snp_report.reported_tcb.microcode.to_string(),
        ),
        ("tcb_snp", snp_report.reported_tcb.snp.to_string()),
        ("tcb_tee", snp_report.reported_tcb.tee.to_string()),
        ("abi_major", snp_report.policy.abi_major().to_string()),
        ("abi_minor", snp_report.policy.abi_minor().to_string()),
        (
            "single_socket",
            snp_report.policy.single_socket_required().to_string(),
        ),
        ("smt_allowed", snp_report.policy.smt_allowed().to_string()),
        (
            "smt_enabled",
            snp_report.plat_info.smt_enabled().to_string(),
        ),
        (
            "tsme_enabled",
            snp_report.plat_info.tsme_enabled().to_string(),
        ),
    ]);

    for (name, value) in &reference_values {
        let output = Command::new("sudo")
            .args([
                "-E",
                &get_kbs_client_path(),
                "--url",
                &format!("https://{escrow_url}:8080"),
                "--cert-file",
                &get_https_cert(),
                "config",
                "--auth-private-key",
                &get_kbs_key(),
                "set-sample-reference-value",
                name,
                value,
            ])
            .output()?;

        if !output.status.success() {
            let reason = format!("error setting reference value (name={name})");
            error!("set_reference_values(): {reason}");
            error!(
                "set_resource_policy(): stdout: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            error!(
                "set_resource_policy(): stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            anyhow::bail!(reason);
        }
    }

    Ok(())
}

async fn set_attestation_policy(escrow_url: &str) -> Result<()> {
    let tee_att_policy_rego = r#"
package policy
import rego.v1

default executables := 33
default hardware := 97
default configuration := 36
default file_system := 0
default instance_identity := 0
default runtime_opaque := 0
default storage_opaque := 0
default sourced_data := 0

az := input.az_snp_vtpm

executables := 3 if {
    az
    az.measurement in query_reference_value("measurement")
    az.tpm.pcr11 in query_reference_value("snp_pcr11")
}

hardware := 2 if {
    az
    az.reported_tcb_bootloader in query_reference_value("tcb_bootloader")
    az.reported_tcb_microcode in query_reference_value("tcb_microcode")
    az.reported_tcb_snp in query_reference_value("tcb_snp")
    az.reported_tcb_tee in query_reference_value("tcb_tee")
}

configuration := 2 if {
    az
    az.platform_smt_enabled in query_reference_value("smt_enabled")
    az.platform_tsme_enabled in query_reference_value("tsme_enabled")
    az.policy_abi_major in query_reference_value("abi_major")
    az.policy_abi_minor in query_reference_value("abi_minor")
    az.policy_single_socket in query_reference_value("single_socket")
    az.policy_smt_allowed in query_reference_value("smt_allowed")
}

trust_claims := {
    "executables": executables,
    "hardware": hardware,
    "configuration": configuration,
    "file-system": file_system,
    "instance-identity": instance_identity,
    "runtime-opaque": runtime_opaque,
    "storage-opaque": storage_opaque,
    "sourced-data": sourced_data,
}
"#;

    let tmp_file = "/tmp/tee_attestation_policy.rego";
    fs::write(tmp_file, &tee_att_policy_rego)?;

    let output = Command::new("sudo")
        .args([
            "-E",
            &get_kbs_client_path(),
            "--url",
            &format!("https://{escrow_url}:8080"),
            "--cert-file",
            &get_https_cert(),
            "config",
            "--auth-private-key",
            &get_kbs_key(),
            "set-attestation-policy",
            "--policy-file",
            tmp_file,
        ])
        .output()?;

    if !output.status.success() {
        let reason = "error setting attestation policy";
        error!("set_attestation_policy(): {reason}");
        error!(
            "set_attestation_policy(): stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        error!(
            "set_attestation_policy(): stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!(reason);
    }

    Ok(())
}

async fn set_resource_policy(escrow_url: &str) -> Result<()> {
    let tee_policy_rego = format!(
        r#"
package policy
default allow = false
allow if {{
    az := input.submods.cpu0["ear.veraison.annotated-evidence"]["{}"]

    # Overall appraisal must be good.
    # input.submods.cpu0["ear.status"] == "affirming"
}}
"#,
        TEE
    );

    let tmp_file = "/tmp/tee_policy.rego";
    fs::write(tmp_file, &tee_policy_rego)?;

    let output = Command::new("sudo")
        .args([
            "-E",
            &get_kbs_client_path(),
            "--url",
            &format!("https://{escrow_url}:8080"),
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

    if !output.status.success() {
        let reason = "error setting resource policy";
        error!("set_resource_policy(): {reason}");
        error!(
            "set_resource_policy(): stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        error!(
            "set_resource_policy(): stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!(reason);
    }

    Ok(())
}

async fn generate_attestation_token(escrow_url: &str) -> Result<()> {
    let output = Command::new("sudo")
        .args([
            "-E",
            &get_kbs_client_path(),
            "--url",
            &format!("https://{escrow_url}:8080"),
            "--cert-file",
            &get_https_cert(),
            "attest",
            "--tee-key-file",
            &get_tee_key(),
        ])
        .output()?;

    if !output.status.success() {
        let reason = "error generating attestation token";
        error!("generate_attestation_token(): {reason}");
        error!(
            "generate_attestation_token(): stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        error!(
            "generate_attestation_token(): stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!(reason);
    }

    fs::write(get_attestation_token(), output.stdout)?;

    Ok(())
}

pub async fn get_trustee_resource(escrow_url: String) -> Result<()> {
    let output = Command::new("sudo")
        .args([
            "-E",
            &get_kbs_client_path(),
            "--url",
            &format!("https://{escrow_url}:8080"),
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

    if !output.status.success() {
        let reason = "error getting trustee resource";
        error!("get_trustee_resource(): {reason}");
        error!(
            "get_trustee_resource(): stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        error!(
            "get_trustee_resource(): stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!(reason);
    }

    Ok(())
}

// -------------------------------------------------------------------------
// Managed HSM methods and constants
// -------------------------------------------------------------------------

/// The individual request to the managed HSM is to wrap a payload using
/// the policy-protected key. To unlock the key we must provide a valid
/// attestation token from MAA.
pub async fn wrap_key_in_mhsm(escrow_url: String) -> Result<()> {
    let azure_attest_bin_path = format!(
        "/home/{}/git/azure/confidential-computing-cvm-guest-attestation\
        /cvm-securekey-release-app/build",
        azure::AZURE_USERNAME
    );

    // This method is ran from the client SNP cVM in Azure, so we cannot
    // use create::Azure (i.e. `az`) to query for the resource URIs
    let az_kv_kid = format!(
        "https://{}.vault.azure.net/keys/{}",
        experiments::MHSM_NAME,
        experiments::MHSM_KEY
    );

    Command::new("sudo")
        .args([
            format!("{azure_attest_bin_path}/AzureAttestSKR").as_str(),
            "-a",
            &escrow_url,
            "-k",
            &az_kv_kid,
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
            EscrowBaseline::ManagedHSM => {
                let owned_escrow_url = escrow_url.to_string();
                tokio::spawn(wrap_key_in_mhsm(owned_escrow_url))
            }
            EscrowBaseline::Accless
            | EscrowBaseline::AcclessMaa
            | EscrowBaseline::AcclessSingleAuth => {
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
        // We set the reference values from this vTPM. This is not secure, as
        // ideally this would come from a source of truth, not the entity
        // itelf we are trying to attest.
        set_reference_values(escrow_url).await?;
        set_attestation_policy(escrow_url).await?;
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
        EscrowBaseline::Accless
        | EscrowBaseline::AcclessMaa
        | EscrowBaseline::AcclessSingleAuth => REQUEST_COUNTS_ACCLESS,
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
        EscrowBaseline::Accless | EscrowBaseline::AcclessSingleAuth => {
            // These paths are hard-coded during the Ansible provisioning of
            // the attestation-service.
            let mut cert_paths = vec![];
            let cert_path_base = host_cert_dir_to_target_path(
                &Env::proj_root()
                    .join("config")
                    .join("attestation-service")
                    .join("certs"),
                &ApplicationBackend::Docker,
            )?;
            for i in 0..(escrow_url.matches(",").count() + 1) {
                cert_paths.push(
                    cert_path_base
                        .join(format!("accless-as-{i}.pem"))
                        .display()
                        .to_string(),
                );
            }
            let num_reqs = request_counts
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",");

            Applications::run(
                &ApplicationType::Function,
                &ApplicationName::EscrowXput,
                &ApplicationBackend::Docker,
                false,
                None,
                vec![
                    "--as-urls".to_string(),
                    escrow_url.to_string(),
                    "--as-cert-paths".to_string(),
                    cert_paths.join(","),
                    "--num-warmup-repeats".to_string(),
                    run_args.num_warmup_repeats.to_string(),
                    "--num-repeats".to_string(),
                    run_args.num_repeats.to_string(),
                    "--num-requests".to_string(),
                    num_reqs,
                    "--results-file".to_string(),
                    Docker::remap_to_docker_path(&results_file)?
                        .display()
                        .to_string(),
                ],
            )?;
        }
        EscrowBaseline::AcclessMaa => {
            let num_reqs = request_counts
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",");

            Applications::run(
                &ApplicationType::Function,
                &ApplicationName::EscrowXput,
                &ApplicationBackend::Docker,
                true, // Must run application as root.
                // When running the Accless MAA baseline, we need additional access to the TPM
                // logs, as required by the Azure library. We currently don't need these for
                // Accless, so instead of making them available in the container by default, we
                // just add some low-level tweaks to the docker command.
                Some(&[
                    "--privileged",
                    "--device=/dev/tpm0",
                    "--mount",
                    "type=bind,src=/sys/kernel/security,dst=/sys/kernel/security,ro",
                ]),
                vec![
                    "--maa".to_string(),
                    "--maa-url".to_string(),
                    escrow_url.to_string(),
                    "--num-warmup-repeats".to_string(),
                    run_args.num_warmup_repeats.to_string(),
                    "--num-repeats".to_string(),
                    run_args.num_repeats.to_string(),
                    "--num-requests".to_string(),
                    num_reqs,
                    "--results_file".to_string(),
                    results_file.display().to_string(),
                ],
            )?;

            // Chown the results file.
            let status = Command::new("sudo")
                .arg("chown")
                .arg(format!(
                    "{}:{}",
                    azure::AZURE_USERNAME,
                    azure::AZURE_USERNAME
                ))
                .arg(results_file.display().to_string())
                .status()?;
            if !status.success() {
                let reason = format!("command failed (status={status})");
                error!("run_escrow_ubench(): {reason}");
                anyhow::bail!(reason);
            }
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
        let mut cmd_in_vm = vec![
            "./scripts/accli_wrapper.sh".to_string(),
            "experiments".to_string(),
            "escrow-xput".to_string(),
            "run".to_string(),
            "--num-repeats".to_string(),
            run_args.num_repeats.to_string(),
            "--num-warmup-repeats".to_string(),
            run_args.num_warmup_repeats.to_string(),
            "--baseline".to_string(),
            format!("{}", run_args.baseline),
        ];

        let client_vm_name = match &run_args.baseline {
            EscrowBaseline::Trustee => {
                cmd_in_vm.push("--escrow-url".to_string());
                cmd_in_vm.push(Azure::get_vm_ip(experiments::TRUSTEE_SERVER_VM_NAME)?);

                experiments::TRUSTEE_CLIENT_VM_NAME
            }
            baseline @ (EscrowBaseline::Accless | EscrowBaseline::AcclessSingleAuth) => {
                // Decide number of attestation-services based on baseline.
                let num_as = if matches!(baseline, EscrowBaseline::Accless) {
                    experiments::ACCLESS_NUM_ATTESTATION_SERVICES
                } else {
                    1
                };
                let mut as_urls = vec![];

                for i in 0..num_as {
                    let as_ip = Azure::get_vm_ip(&format!(
                        "{}-{i}",
                        experiments::ACCLESS_ATTESTATION_SERVICE_BASE_VM_NAME
                    ))?;
                    as_urls.push(format!("https://{as_ip}:8443"));
                }

                cmd_in_vm.push("--escrow-url".to_string());
                cmd_in_vm.push(as_urls.join(","));

                experiments::ACCLESS_VM_NAME
            }
            EscrowBaseline::AcclessMaa => {
                cmd_in_vm.push("--escrow-url".to_string());
                cmd_in_vm.push(Azure::get_aa_attest_uri(experiments::ACCLESS_MAA_NAME)?);

                experiments::ACCLESS_VM_NAME
            }
            EscrowBaseline::ManagedHSM => {
                cmd_in_vm.push("--escrow-url".to_string());
                cmd_in_vm.push(Azure::get_aa_attest_uri(
                    experiments::MHSM_ATTESTATION_SERVICE_NAME,
                )?);

                experiments::MHSM_CLIENT_VM_NAME
            }
        };

        // Run experiment in Azure VM.
        Azure::run_cmd_in_vm(
            client_vm_name,
            &cmd_in_vm,
            Some(experiments::ACCLESS_VM_CODE_DIR),
        )?;

        // SCP results.
        let src_results = format!(
            "{client_vm_name}:{}/experiments/{}/data/{}.csv",
            experiments::ACCLESS_VM_CODE_DIR,
            Experiment::ESCROW_XPUT_NAME,
            run_args.baseline
        );
        let dst_results = Env::experiments_root()
            .join(Experiment::ESCROW_XPUT_NAME)
            .join("data")
            .join(format!("{}.csv", run_args.baseline));
        Azure::run_scp_cmd(&src_results, &dst_results.display().to_string())?;

        return Ok(());
    }

    // Get the escrow URL.
    if run_args.escrow_url.is_none() {
        let reason = "running baseline in azure VM but no escrow URL provided";
        error!("run(): {reason}");
        anyhow::bail!(reason);
    }
    let escrow_url = run_args.escrow_url.clone().unwrap();

    match ubench {
        Experiment::EscrowCost { .. } => anyhow::bail!("escrow-cost is not meant to be ran"),
        Experiment::EscrowXput { .. } => run_escrow_ubench(&escrow_url, run_args).await,
        _ => anyhow::bail!("experiment not a micro-benchmark (experiment={ubench:?})"),
    }
}

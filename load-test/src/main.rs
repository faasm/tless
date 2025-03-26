use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::process::Command;
use std::time::Instant;
use tokio::fs;
use csv::Writer;
use serde::Serialize;

// TODO: may make this variables
const PARALLELISM: usize = 100;
const REPETITIONS: usize = 5;
const REQUEST_COUNTS: &[usize] = &[1, 10, 100, 1000];

// TODO: may have to change this
const TEE: &str = "sample";

const KBS_CLIENT_PATH: &str = "/home/tless/git/confidential-containers/trustee/target/release/kbs-client";
const KBS_URL: &str = "https://127.0.0.1:8080";

const WORK_DIR: &str = "/home/tless/git/confidential-containers/trustee/kbs/test/work";

fn get_attestation_token() -> String {
    format!("{WORK_DIR}/attestation_token")
}

fn get_https_cert() -> String {
    format!("{WORK_DIR}/https.crt")
}

fn get_kbs_key() -> String {
    format!("{WORK_DIR}/kbs.key")
}

fn get_tee_key() -> String {
    format!("{WORK_DIR}/tee.key")
}

#[derive(Serialize)]
struct Record {
    num_requests: usize,
    time_elapsed: f64,
}

async fn generate_attestation_token() -> Result<()> {
    let output = Command::new("sudo")
        .args(["-E", KBS_CLIENT_PATH,
               "--url", KBS_URL,
               "--cert-file", &get_https_cert(),
               "attest",
               "--tee-key-file", &get_tee_key()])
        .output()?;

    fs::write(&get_attestation_token(), output.stdout).await?;

    Ok(())
}

async fn set_resource_policy() -> Result<()> {
    let tee_policy_rego = format!(r#"
package policy
default allow = false
allow {{
    input["submods"]["cpu"]["ear.veraison.annotated-evidence"]["{}"]
}}
"#, TEE);

    let tmp_file = "/tmp/tee_policy.rego";
    fs::write(tmp_file, &tee_policy_rego).await?;

    Command::new("sudo")
        .args(["-E", KBS_CLIENT_PATH,
               "--url", KBS_URL,
               "--cert-file", &get_https_cert(),
               "config",
               "--auth-private-key", &get_kbs_key(),
               "set-resource-policy",
               "--policy-file", tmp_file])
        .status()?;

    Ok(())
}

async fn get_resource() -> Result<()> {
    Command::new("sudo")
        .args(["-E", KBS_CLIENT_PATH,
               "--url", KBS_URL,
               "--cert-file", &get_https_cert(),
               "get-resource",
               "--tee-key-file", &get_tee_key(),
               "--attestation-token", &get_attestation_token(),
               "--path", "one/two/three"])
        .status()?;

    Ok(())
}

async fn measure_requests(num_requests: usize) -> Result<f64> {
    println!("Processing {} requests with parallelism={}...", num_requests, PARALLELISM);

    let start = Instant::now();

    stream::iter(0..num_requests)
        .map(|_| tokio::spawn(get_resource()))
        .buffer_unordered(PARALLELISM)
        .for_each(|res| async {
            if let Err(e) = res {
                eprintln!("Task failed: {:?}", e);
            }
        })
        .await;

    let elapsed = start.elapsed().as_secs_f64();
    println!("Total time: {:.4}s", elapsed);

    Ok(elapsed)
}

async fn run_load_test() -> Result<()> {
    fs::create_dir_all(WORK_DIR).await?;

    let mut wtr = Writer::from_path("results.csv")?;
    wtr.write_record(["num_requests", "time_elapsed"])?;

    for &num_req in REQUEST_COUNTS {
        for _ in 0..REPETITIONS {
            let elapsed = measure_requests(num_req).await?;
            wtr.serialize(Record { num_requests: num_req, time_elapsed: elapsed })?;
        }
    }
    wtr.flush()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    generate_attestation_token().await?;
    set_resource_policy().await?;
    get_resource().await?;

    // run_load_test().await?;

    Ok(())
}


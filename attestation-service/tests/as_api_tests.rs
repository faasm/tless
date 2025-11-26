use accli::tasks::applications::{ApplicationName, ApplicationType, Applications};
use anyhow::Result;
use log::{error, info};
use reqwest::Client;
use serde_json::Value;
use serial_test::serial;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tempfile::tempdir;
use tokio::process::{Child, Command};

struct ChildGuard(Child);

// ===============================================================================================
// Helper Functions
// ===============================================================================================

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn spawn_as(certs_dir: &str, clean_certs: bool, mock: bool) -> Result<Child> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_attestation-service"));
    cmd.arg("--certs-dir")
        .arg(certs_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if clean_certs {
        cmd.arg("--force-clean-certs");
    }

    if mock {
        cmd.arg("--mock");
    }

    Ok(cmd.spawn()?)
}

pub fn get_public_certificate_path(certs_dir: &Path) -> PathBuf {
    certs_dir.join("cert.pem")
}

async fn health_check(client: &Client) -> Result<()> {
    let mut attempts = 0;
    let max_attempts = 5;
    let mut delay = Duration::from_secs(1);

    loop {
        match client.get("https://localhost:8443/health").send().await {
            Ok(res) if res.status().is_success() => return Ok(()),
            _ => {
                attempts += 1;
                if attempts >= max_attempts {
                    return Err(anyhow::anyhow!(
                        "Health check failed after {} attempts",
                        max_attempts
                    ));
                }
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
}

// ===============================================================================================
// Tests
// ===============================================================================================

#[tokio::test]
#[serial]
async fn test_spawn_as() -> Result<()> {
    let temp_dir = tempdir()?;
    let certs_dir = temp_dir.path();
    let child = spawn_as(certs_dir.to_str().unwrap(), true, false)?;
    let _child_guard = ChildGuard(child);

    // Give the service time to start.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client).await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_spawn_as_no_clean() -> Result<()> {
    let temp_dir = tempdir()?;
    let certs_dir = temp_dir.path();
    let child = spawn_as(certs_dir.to_str().unwrap(), false, false)?;
    let _child_guard = ChildGuard(child);
    // Give the service time to start.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client).await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_att_clients() -> Result<()> {
    attestation_service::init_logging();

    let certs_dir = Path::new(env!("ACCLESS_ROOT_DIR"))
        .join("config")
        .join("attestation-service")
        .join("test-certs");
    let child = spawn_as(certs_dir.to_str().unwrap(), true, true)?;
    let _child_guard = ChildGuard(child);

    // Give the service time to start.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let cert_path = get_public_certificate_path(&certs_dir);

    // While it is starting, rebuild the test application so that we can inject the
    // new certificates. Note that we need to pass the certificate's path
    // _inside_ the container, as application build happens inside the
    // container. We also _must_ set the `clean` flag to true, to force
    // recompilation.
    info!("re-building mock clients with new certificates, this will take a while...");
    Applications::build(true, false, Some(cert_path.clone()), true, false)?;

    // Health-check the attestation service.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client).await?;

    // Run the client applications inside the container.
    let as_url = "https://127.0.0.1:8443".to_string();

    info!("running mock sgx client...");
    Applications::run(
        ApplicationType::Test,
        ApplicationName::AttClientSgx,
        false,
        Some(as_url.clone()),
        Some(cert_path.clone()),
    )?;

    info!("running mock snp client...");
    Applications::run(
        ApplicationType::Test,
        ApplicationName::AttClientSnp,
        false,
        Some(as_url),
        Some(cert_path),
    )?;

    match std::fs::remove_dir_all(&certs_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            error!("error removing certs dir (error={e:?}, dir={certs_dir:?})");
        }
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_get_state() -> Result<()> {
    let temp_dir = tempdir()?;
    let certs_dir = temp_dir.path();
    let child = spawn_as(certs_dir.to_str().unwrap(), true, false)?;
    let _child_guard = ChildGuard(child);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client).await?;

    let res = client.get("https://localhost:8443/state").send().await?;
    assert!(res.status().is_success());

    let body: Value = res.json().await?;
    assert!(body.get("id").is_some());
    assert!(body.get("id").unwrap().is_string());
    assert!(body.get("mpk").is_some());
    assert!(body.get("mpk").unwrap().is_string());

    Ok(())
}

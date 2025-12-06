use accli::tasks::applications::{
    ApplicationBackend, ApplicationName, ApplicationType, Applications,
    host_cert_dir_to_target_path,
};
use anyhow::Result;
use log::{error, info};
use reqwest::Client;
use serde_json::Value;
use serial_test::serial;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use tokio::{
    process::{Child, Command},
    time::sleep,
};

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

    let cert_path = get_public_certificate_path(&certs_dir);

    // Wait until cert path to be ready.
    let deadline = Instant::now() + Duration::from_secs(15);
    let poll_interval = Duration::from_millis(100);
    loop {
        if cert_path.exists() {
            break;
        }
        if Instant::now() >= deadline {
            let reason = format!(
                "timed-out waiting for certs to become available (path={})",
                cert_path.display()
            );
            error!("test_att_clients(): {reason}");
            anyhow::bail!(reason);
        }

        sleep(poll_interval).await;
    }

    // While it is starting, rebuild the test application so that we can inject the
    // new certificates. Note that we need to pass the certificate's path
    // _inside_ the container, as application build happens inside the
    // container. We also _must_ set the `clean` flag to true, to force
    // recompilation.
    info!("re-building mock clients with new certificates, this will take a while...");
    Applications::build(
        true,
        false,
        Some(certs_dir.clone().to_path_buf()),
        true,
        false,
    )?;

    // Health-check the attestation service.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client).await?;

    // Run the client applications inside the container.
    let as_url = "https://127.0.0.1:8443".to_string();

    info!("running mock sgx client...");
    Applications::run(
        &ApplicationType::Test,
        &ApplicationName::AttClientSgx,
        &ApplicationBackend::Docker,
        false,
        None,
        vec![
            "--as-url".to_string(),
            as_url.clone(),
            "--as-cert-path".to_string(),
            get_public_certificate_path(&host_cert_dir_to_target_path(
                &certs_dir,
                &ApplicationBackend::Docker,
            )?)
            .display()
            .to_string(),
        ],
    )?;

    info!("running mock snp client...");
    Applications::run(
        &ApplicationType::Test,
        &ApplicationName::AttClientSnp,
        &ApplicationBackend::Docker,
        false,
        None,
        vec![
            "--as-url".to_string(),
            as_url.clone(),
            "--as-cert-path".to_string(),
            get_public_certificate_path(&host_cert_dir_to_target_path(
                &certs_dir,
                &ApplicationBackend::Docker,
            )?)
            .display()
            .to_string(),
        ],
    )?;

    match fs::remove_dir_all(&certs_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            error!("test_att_clients(): error removing certs dir (error={e:?}, dir={certs_dir:?})");
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

#[tokio::test]
#[serial]
async fn test_multi_as() -> Result<()> {
    attestation_service::init_logging();

    let certs_dir_1 = tempdir()?;
    let certs_dir_2 = tempdir()?;

    let mut cmd_1 = Command::new(env!("CARGO_BIN_EXE_attestation-service"));
    cmd_1.arg("--certs-dir").arg(certs_dir_1.path());
    cmd_1.arg("--port").arg("8443");
    cmd_1.arg("--id").arg("as1");
    cmd_1.arg("--force-clean-certs");
    cmd_1.arg("--mock");
    let _child1 = ChildGuard(cmd_1.spawn()?);

    let mut cmd_2 = Command::new(env!("CARGO_BIN_EXE_attestation-service"));
    cmd_2.arg("--certs-dir").arg(certs_dir_2.path());
    cmd_2.arg("--port").arg("8444");
    cmd_2.arg("--id").arg("as2");
    cmd_2.arg("--force-clean-certs");
    cmd_2.arg("--mock");
    let _child2 = ChildGuard(cmd_2.spawn()?);

    let cert_path_1 = get_public_certificate_path(certs_dir_1.path());
    let cert_path_2 = get_public_certificate_path(certs_dir_2.path());

    for cert_path in [cert_path_1.clone(), cert_path_2.clone()] {
        let deadline = Instant::now() + Duration::from_secs(15);
        let poll_interval = Duration::from_millis(100);
        loop {
            if cert_path.exists() {
                break;
            }
            if Instant::now() >= deadline {
                let reason = format!(
                    "timed-out waiting for certs to become available (path={})",
                    cert_path.display()
                );
                error!("test_multi_as(): {reason}");
                anyhow::bail!(reason);
            }

            sleep(poll_interval).await;
        }
    }

    let merged_certs_dir = Path::new(env!("ACCLESS_ROOT_DIR"))
        .join("config")
        .join("attestation-service")
        .join("test-certs");
    fs::create_dir_all(&merged_certs_dir)?;
    fs::copy(&cert_path_1, merged_certs_dir.join("cert1.pem"))?;
    fs::copy(&cert_path_2, merged_certs_dir.join("cert2.pem"))?;

    info!(
        "test_multi_as(): re-building multi-as client with new certificates, this will take a while..."
    );
    let merged_certs_dir_docker =
        host_cert_dir_to_target_path(&merged_certs_dir, &ApplicationBackend::Docker)?;
    Applications::build(
        true,
        false,
        Some(merged_certs_dir.to_path_buf()),
        true,
        false,
    )?;

    let client1 = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client1).await?;
    let client2 = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client2).await?;

    // Convert full paths to paths relative to the docker mount point.
    let cert_path_1_docker = merged_certs_dir_docker.join("cert1.pem");
    let cert_path_2_docker = merged_certs_dir_docker.join("cert2.pem");

    info!("running mock multi-as client...");
    Applications::run(
        &ApplicationType::Test,
        &ApplicationName::MultiAs,
        &ApplicationBackend::Docker,
        false,
        None,
        vec![
            "--as-urls".to_string(),
            "https://localhost:8443,https://localhost:8444".to_string(),
            "--as-cert-paths".to_string(),
            format!(
                "{},{}",
                cert_path_1_docker.display(),
                cert_path_2_docker.display()
            ),
        ],
    )?;

    match fs::remove_dir_all(&merged_certs_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            error!(
                "test_multi_as(): error removing certs dir (error={e:?}, dir={merged_certs_dir:?})"
            );
        }
    }

    Ok(())
}

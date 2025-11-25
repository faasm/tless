use accli::tasks::{
    applications::Applications,
    docker::{DOCKER_ACCLESS_CODE_MOUNT_DIR, Docker},
};
use anyhow::Result;
use log::{error, info};
use reqwest::Client;
use serde_json::Value;
use serial_test::serial;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::tempdir;
use tokio::process::Child;

mod common;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

// FIXME: I doubt this is working
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

/// # Description
///
/// Get the path of SGX's attestation client from _inside_ the docker container.
fn get_att_client_sgx_path_in_ctr() -> Result<PathBuf> {
    let path = PathBuf::from(DOCKER_ACCLESS_CODE_MOUNT_DIR)
        .join("applications")
        .join("build-native")
        .join("test")
        .join("att-client-sgx")
        .join("att-client-sgx");

    Ok(path)
}

/// # Description
///
/// Get the path of SNP's attestation client from _inside_ the docker container.
fn get_att_client_snp_path_in_ctr() -> Result<PathBuf> {
    let path = PathBuf::from(DOCKER_ACCLESS_CODE_MOUNT_DIR)
        .join("applications")
        .join("build-native")
        .join("test")
        .join("att-client-snp")
        .join("att-client-snp");

    Ok(path)
}

/// # Description
///
/// Remap an absolute path the host to the mounted container.
pub fn remap_host_path_to_container(host_path: &Path) -> Result<PathBuf> {
    let prefix = Path::new(env!("ACCLESS_ROOT_DIR"));
    let rel = host_path.strip_prefix(prefix)?;
    Ok(Path::new("/code/accless").join(rel))
}

#[tokio::test]
#[serial]
async fn test_spawn_as() -> Result<()> {
    let temp_dir = tempdir()?;
    let certs_dir = temp_dir.path();
    let child = common::spawn_as(certs_dir.to_str().unwrap(), true, false)?;
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
    let child = common::spawn_as(certs_dir.to_str().unwrap(), false, false)?;
    let _child_guard = ChildGuard(child);
    // Give the service time to start.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client).await?;

    Ok(())
}

/// WARNING: this test relies on `accli` and on the test applications being
/// compiled. The former can be (re-)compiled with `cargo build -p accli` and
/// the latter with `accli applications build test`
#[tokio::test]
#[serial]
async fn test_att_clients() -> Result<()> {
    attestation_service::init_logging();

    let certs_dir = Path::new(env!("ACCLESS_ROOT_DIR"))
        .join("config")
        .join("test-certs");
    let child = common::spawn_as(certs_dir.to_str().unwrap(), true, true)?;
    let _child_guard = ChildGuard(child);

    // Give the service time to start.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let cert_path =
        remap_host_path_to_container(&crate::common::get_public_certificate_path(&certs_dir))?;

    // While it is starting, rebuild the test application so that we can inject the
    // new certificates. Note that we need to pass the certificate's path
    // _inside_ the container, as application build happens inside the
    // container. We also _must_ set the `clean` flag to true, to force
    // recompilation.
    info!("re-building mock clients with new certificates, this will take a while...");
    Applications::build(true, false, cert_path.to_str(), true, false)?;

    // Health-check the attestation service.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client).await?;

    // Run the client applications inside the container.
    let att_client_sgx_path = get_att_client_sgx_path_in_ctr()?;
    let att_client_snp_path = get_att_client_snp_path_in_ctr()?;
    let env_vars = [
        "ACCLESS_AS_URL=https://127.0.0.1:8443".to_string(),
        format!("ACCLESS_AS_CERT_PATH={}", cert_path.display()),
    ];

    info!("running mock sgx client...");
    Docker::run(
        &[att_client_sgx_path.display().to_string()],
        true,
        None,
        &env_vars,
        true,
        false,
    )?;

    info!("running mock snp client...");
    Docker::run(
        &[att_client_snp_path.display().to_string()],
        true,
        None,
        &env_vars,
        true,
        false,
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
    let child = common::spawn_as(certs_dir.to_str().unwrap(), true, false)?;
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

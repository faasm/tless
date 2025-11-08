use anyhow::Result;
use reqwest::Client;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::tempdir;
use tokio::process::{Child, Command};

const CTR_ROOT: &'static str = "/code/accless";

mod common;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

// FIXME: I doubt this is working
async fn health_check(client: &Client) -> Result<()> {
    let res = client.get("https://localhost:8443/health").send().await?;
    assert!(res.status().is_success());
    Ok(())
}

/// # Description
///
/// Get the path of SGX's attestation client from _inside_ the docker container.
fn get_att_client_sgx_path_in_ctr() -> Result<PathBuf> {
    let path = PathBuf::from(CTR_ROOT)
        .join("applications")
        .join("build-native")
        .join("test")
        .join("att-client-sgx")
        .join("att-client-sgx");

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

/// # Description
///
/// Get the path of accli to launch a docker container.
fn get_accli_path() -> Result<PathBuf> {
    let path = PathBuf::from(env!("ACCLESS_ROOT_DIR"))
        .join("target")
        .join("release")
        .join("accli");
    if !path.exists() {
        return Err(anyhow::anyhow!("accli not found at: {:?}", path));
    }
    Ok(path)
}

#[tokio::test]
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
async fn test_att_client_sgx() -> Result<()> {
    let temp_dir = tempdir()?;
    let certs_dir = temp_dir.path();
    let child = common::spawn_as(certs_dir.to_str().unwrap(), true, true)?;
    let _child_guard = ChildGuard(child);

    // Give the service time to start.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    health_check(&client).await?;

    // FINISH ME: call inside the container!
    let accli_path = get_accli_path()?;
    let att_client_sgx_path = get_att_client_sgx_path_in_ctr()?;
    let cert_path =
        remap_host_path_to_container(&crate::common::get_public_certificate_path(certs_dir))?;
    let output = Command::new(accli_path)
        .arg("docker")
        .arg("run")
        .arg("--mount")
        .arg("--net")
        .arg("--env")
        .arg("ACCLESS_AS_URL=\"https://0.0.0.0:8443\"")
        .arg("--env")
        .arg(format!("ACCLESS_AS_CERT_PATH={}", cert_path.display()))
        .arg(att_client_sgx_path)
        .output()
        .await?;

    println!(
        "att-client-sgx stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    println!(
        "att-client-sgx stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success());

    Ok(())
}

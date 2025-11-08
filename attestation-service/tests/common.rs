use anyhow::Result;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::process::{Child, Command};

pub fn spawn_as(certs_dir: &str, clean_certs: bool) -> Result<Child> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_attestation-service"));
    cmd.arg("--certs-dir")
        .arg(certs_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if clean_certs {
        cmd.arg("--force-clean-certs");
    }
    Ok(cmd.spawn()?)
}

pub fn get_public_certificate_path(certs_dir: &Path) -> PathBuf {
    certs_dir.join("cert.pem")
}

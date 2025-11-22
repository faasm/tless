use crate::tasks::docker::{DOCKER_ACCLESS_CODE_MOUNT_DIR, Docker};
use std::path::Path;

#[derive(Debug)]
pub struct Applications {}

impl Applications {
    pub fn build(
        clean: bool,
        debug: bool,
        cert_path: Option<&str>,
        capture_output: bool,
    ) -> anyhow::Result<Option<String>> {
        let mut cmd = vec!["python3".to_string(), "build.py".to_string()];
        if clean {
            cmd.push("--clean".to_string());
        }
        if debug {
            cmd.push("--debug".to_string());
        }
        if let Some(cert_path_str) = cert_path {
            let cert_path = Path::new(cert_path_str);
            if !cert_path.exists() {
                anyhow::bail!("Certificate path does not exist: {}", cert_path.display());
            }
            if !cert_path.is_file() {
                anyhow::bail!("Certificate path is not a file: {}", cert_path.display());
            }
            let docker_cert_path = Docker::get_docker_path(cert_path)?;
            cmd.push("--cert-path".to_string());
            let docker_cert_path_str = docker_cert_path.to_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "Docker path for certificate is not valid UTF-8: {}",
                    docker_cert_path.display()
                )
            })?;
            cmd.push(docker_cert_path_str.to_string());
        }
        let workdir = Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR).join("applications");
        let workdir_str = workdir.to_str().ok_or_else(|| {
            anyhow::anyhow!("Workdir path is not valid UTF-8: {}", workdir.display())
        })?;
        Docker::run(&cmd, true, Some(workdir_str), &[], false, capture_output)
    }
}

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
        if let Some(cert_path) = cert_path {
            cmd.push("--cert-path".to_string());
            cmd.push(cert_path.to_string());
        }
        let workdir = Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR).join("applications");
        Docker::run(
            &cmd,
            true,
            Some(workdir.to_str().unwrap()),
            &[],
            false,
            capture_output,
        )
    }
}

use crate::tasks::docker::{DOCKER_ACCLESS_CODE_MOUNT_DIR, Docker};
use std::path::Path;

#[derive(Debug)]
pub struct Accless {}

impl Accless {
    pub fn build(clean: bool, debug: bool) {
        let mut cmd = vec!["python3".to_string(), "build.py".to_string()];
        if clean {
            cmd.push("--clean".to_string());
        }
        if debug {
            cmd.push("--debug".to_string());
        }
        let workdir = Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR).join("accless");
        Docker::run(&cmd, true, Some(workdir.to_str().unwrap()), &[], false);
    }

    pub fn test() {
        let cmd = vec![
            "ctest".to_string(),
            "--".to_string(),
            "--output-on-failure".to_string(),
        ];
        let workdir = Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR).join("accless/build-native");
        Docker::run(&cmd, true, Some(workdir.to_str().unwrap()), &[], false);
    }
}

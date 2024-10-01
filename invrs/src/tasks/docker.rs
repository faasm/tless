use crate::env::Env;
use std::process::{Command, Stdio};

#[derive(Debug)]
pub struct Docker {}

impl Docker {
    pub fn get_docker_tag(ctr_name: String) -> String {
        // Prepare image tag
        let version = match Env::get_version() {
            Ok(ver) => ver,
            Err(e) => {
                panic!("invrs(docker): error getting version from file: {}", e);
            }
        };

        format!("{}/{}:{}", Env::CONTAINER_REGISTRY_URL, ctr_name, version)
    }

    fn do_build(ctr_name: String, nocache: bool) {
        // Prepare dockerfile path
        let mut dockerfile_path = Env::docker_root();
        dockerfile_path.push(format!("{ctr_name}.dockerfile"));

        let image_tag = Self::get_docker_tag(ctr_name);

        // Set arguments for the command
        let mut cmd = Command::new("docker");
        cmd.env("DOCKER_BUILDKIT", "1");
        cmd.current_dir(Env::proj_root());

        cmd.arg("build")
            .arg("-t")
            .arg(image_tag)
            .arg("-f")
            .arg(dockerfile_path.to_string_lossy().into_owned())
            .arg("--build-arg")
            .arg(format!("TLESS_VERSION={}", Env::get_version().unwrap()))
            .arg(".");

        if nocache {
            cmd.arg("--no-cache");
        }

        cmd.stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("invrs: failed executing command");
    }

    fn do_push(ctr_name: String) {
        let image_tag = Self::get_docker_tag(ctr_name);

        // Set arguments for the command
        let mut cmd = Command::new("docker");
        cmd.env("DOCKER_BUILDKIT", "1");
        cmd.current_dir(Env::proj_root());

        cmd.arg("push")
            .arg(image_tag)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("invrs: failed executing command");
    }

    pub fn build(ctr_name: String, push: bool, nocache: bool) {
        Self::do_build(ctr_name.clone(), nocache);

        if push {
            Self::do_push(ctr_name.clone());
        }
    }
}

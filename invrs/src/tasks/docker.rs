use crate::env::Env;
use std::process::{Command, Stdio};

#[derive(Debug)]
pub struct Docker {}

impl Docker {
    pub fn do_cmd(cmd: String) -> () {
        match cmd.as_str() {
            "build" => Self::build(),
            "push" => Self::push(),
            _ => panic!("invrs: unrecognised command for task 'build': {cmd:?}")
        }
    }

    fn get_docker_tag() -> String {
        // Prepare image tag
        let version;
        match Env::get_version() {
            Ok(ver) => version = ver,
            Err(e) => {
                panic!("invrs: error getting version from file: {}", e);
            }
        }

        format!("{}/tless-experiments:{}", Env::CONTAINER_REGISTRY_URL, version)
    }

    fn build() -> () {
        // Prepare dockerfile path
        let mut dockerfile_path = Env::docker_root();
        dockerfile_path.push("tless-experiments.dockerfile");

        let image_tag = Self::get_docker_tag();

        // Set arguments for the command
        let mut cmd = Command::new("docker");
        cmd.env("DOCKER_BUILDKIT", "1");
        cmd.current_dir(Env::proj_root());

        cmd.arg("build")
           .arg("-t")
           .arg(image_tag)
           .arg("-f")
           .arg(dockerfile_path.to_string_lossy().into_owned())
           .arg("--no-cache")
           .arg(".")
           .stdout(Stdio::inherit())
           .stderr(Stdio::inherit())
           .output()
           .expect("invrs: failed executing command");
    }

    fn push() -> () {
        let image_tag = Self::get_docker_tag();

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
}

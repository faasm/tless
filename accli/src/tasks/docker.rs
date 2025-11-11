use crate::env::Env;
use clap::ValueEnum;
use std::{
    fmt,
    process::{Command, Stdio},
    str::FromStr,
};

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum DockerContainer {
    Experiments,
    Worker,
}

impl fmt::Display for DockerContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DockerContainer::Experiments => write!(f, "accless-experiments"),
            DockerContainer::Worker => write!(f, "accless-knative-worker"),
        }
    }
}

impl FromStr for DockerContainer {
    type Err = ();

    fn from_str(input: &str) -> Result<DockerContainer, Self::Err> {
        match input {
            "accless-experiments" => Ok(DockerContainer::Experiments),
            "accless-knative-worker" => Ok(DockerContainer::Worker),
            _ => Err(()),
        }
    }
}

impl DockerContainer {
    pub fn iter_variants() -> std::slice::Iter<'static, DockerContainer> {
        static VARIANTS: [DockerContainer; 2] =
            [DockerContainer::Experiments, DockerContainer::Worker];
        VARIANTS.iter()
    }
}

#[derive(Debug)]
pub struct Docker {}

pub const DOCKER_ACCLESS_CODE_MOUNT_DIR: &str = "/code/accless";

impl Docker {
    const ACCLESS_DEV_CONTAINER_NAME: &'static str = "accless-dev";

    pub fn get_docker_tag(ctr: &DockerContainer) -> String {
        // Prepare image tag
        let version = match Env::get_version() {
            Ok(ver) => ver,
            Err(e) => {
                panic!("invrs(docker): error getting version from file: {}", e);
            }
        };

        format!("{}/{}:{}", Env::CONTAINER_REGISTRY_URL, ctr, version)
    }

    fn do_build(ctr: &DockerContainer, nocache: bool) {
        // Prepare dockerfile path
        let mut dockerfile_path = Env::docker_root();
        dockerfile_path.push(format!("{}.dockerfile", ctr));

        let image_tag = Self::get_docker_tag(ctr);

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
            .arg(format!("ACCLESS_VERSION={}", Env::get_version().unwrap()))
            .arg(".");

        if nocache {
            cmd.arg("--no-cache");
        }

        cmd.stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .expect("invrs: failed executing command");
    }

    fn do_push(ctr: &DockerContainer) {
        let image_tag = Self::get_docker_tag(ctr);

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

    pub fn build(ctr: &DockerContainer, push: bool, nocache: bool) {
        Self::do_build(ctr, nocache);

        if push {
            Self::do_push(ctr);
        }
    }

    fn is_container_running() -> bool {
        let output = Command::new("docker")
            .arg("ps")
            .arg("-f")
            .arg(format!("name={}", Self::ACCLESS_DEV_CONTAINER_NAME))
            .output()
            .expect("failed to run docker ps");
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.contains(Self::ACCLESS_DEV_CONTAINER_NAME)
    }

    fn get_user_id() -> String {
        let uid = Command::new("id")
            .arg("-u")
            .output()
            .expect("failed to get uid");
        String::from_utf8_lossy(&uid.stdout).trim().to_string()
    }

    fn get_group_id() -> String {
        let gid = Command::new("id")
            .arg("-g")
            .output()
            .expect("failed to get gid");
        String::from_utf8_lossy(&gid.stdout).trim().to_string()
    }

    fn exec_cmd(cmd: &[String], cwd: Option<&str>, interactive: bool) {
        let mut exec_cmd = Command::new("docker");
        exec_cmd.arg("exec");
        if interactive {
            exec_cmd.arg("-it");
        }
        if let Some(workdir) = cwd {
            exec_cmd.arg("-w").arg(workdir);
        }
        exec_cmd.arg(Self::ACCLESS_DEV_CONTAINER_NAME);
        exec_cmd.arg("bash");
        if !cmd.is_empty() {
            exec_cmd.arg("-c").arg(cmd.join(" "));
        }

        exec_cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .expect("failed to execute docker exec");
    }

    fn run_cmd(
        cmd: &[String],
        mount: bool,
        cwd: Option<&str>,
        interactive: bool,
        env: &[String],
        net: bool,
    ) {
        let image_tag = Self::get_docker_tag(&DockerContainer::Experiments);
        let mut run_cmd = Command::new("docker");
        run_cmd
            .arg("run")
            .arg("--rm")
            .arg("--name")
            .arg(Self::ACCLESS_DEV_CONTAINER_NAME);
        if interactive {
            run_cmd.arg("-it");
        }

        run_cmd
            .arg("-e")
            .arg(format!("HOST_UID={}", Self::get_user_id()))
            .arg("-e")
            .arg(format!("HOST_GID={}", Self::get_group_id()));

        for e in env {
            run_cmd.arg("-e").arg(e);
        }

        if net {
            run_cmd.arg("--network").arg("host");
        }

        if mount {
            run_cmd
                .arg("-v")
                .arg(format!("{}:/code/accless", Env::proj_root().display()));
        }
        if let Some(workdir) = cwd {
            run_cmd.arg("--workdir").arg(workdir);
        }

        run_cmd.arg(image_tag);
        if !cmd.is_empty() {
            run_cmd.arg("bash").arg("-c").arg(cmd.join(" "));
        } else if interactive {
            run_cmd.arg("bash");
        }

        run_cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .expect("failed to execute docker run");
    }

    pub fn cli(net: bool) {
        if Self::is_container_running() {
            Self::exec_cmd(&[], Some(DOCKER_ACCLESS_CODE_MOUNT_DIR), true);
        } else {
            Self::run_cmd(
                &[],
                true,
                Some(DOCKER_ACCLESS_CODE_MOUNT_DIR),
                true,
                &[],
                net,
            );
        }
    }

    pub fn run(cmd: &[String], mount: bool, cwd: Option<&str>, env: &[String], net: bool) {
        if Self::is_container_running() {
            if !mount {
                panic!(
                    "Container is already running, but --mount flag was not provided. This is required to ensure code consistency."
                );
            }
            Self::exec_cmd(cmd, cwd, true);
        } else {
            Self::run_cmd(cmd, mount, cwd, true, env, net);
        }
    }
}

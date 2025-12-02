use crate::env::Env;
use anyhow::Result;
use clap::ValueEnum;
use log::error;
use std::{
    fmt,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
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
    const ACCLESS_DEV_CONTAINER_HOSTNAME: &'static str = "accless-ctr";

    /// # Description
    ///
    /// This function takes a path from the host filesystem and maps it to the
    /// corresponding path inside the Docker container.
    /// It first converts the `host_path` to an absolute path and canonicalizes
    /// it. This process also verifies that the path exists.
    /// Then, it checks if the path is within the project's root directory.
    /// If it is, it strips the project root prefix and prepends the Docker
    /// mount directory path (`/code/accless`).
    ///
    /// # Arguments
    ///
    /// * `host_path` - A reference to a `Path` on the host filesystem. It can
    ///   be either an absolute path or a path relative to the current working
    ///   directory.
    ///
    /// # Returns
    ///
    /// A `anyhow::Result<PathBuf>` which is:
    /// - `Ok(PathBuf)`: The mapped path inside the Docker container.
    /// - `Err(anyhow::Error)`: An error if:
    ///   - The path does not exist or cannot be canonicalized.
    ///   - The path is outside the project's root directory.
    pub fn remap_to_docker_path(host_path: &Path) -> Result<PathBuf> {
        let absolute_host_path = if host_path.is_absolute() {
            host_path.to_path_buf()
        } else {
            std::env::current_dir()?.join(host_path)
        };
        let absolute_host_path = absolute_host_path.canonicalize().map_err(|e| {
            anyhow::anyhow!("Error canonicalizing path {}: {}", host_path.display(), e)
        })?;

        let proj_root = Env::proj_root();
        if absolute_host_path.starts_with(&proj_root) {
            let relative_path = absolute_host_path.strip_prefix(&proj_root).unwrap();
            let docker_path = Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR).join(relative_path);
            Ok(docker_path)
        } else {
            anyhow::bail!(
                "Path {} is outside the project root directory {}",
                absolute_host_path.display(),
                proj_root.display()
            );
        }
    }

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

    /// Helper method to get the group ID of the /dev/sev-guest device.
    ///
    /// This method is only used when using `accli` inside a cVM. In our cVM
    /// set-up we configure /dev/sev-guest to be in a shared group with our
    /// user, to avoid having to use `sudo` to run our functions.
    fn get_sevguest_group_id() -> Option<u32> {
        match std::fs::metadata("/dev/sev-guest") {
            Ok(metadata) => Some(metadata.gid()),
            Err(_) => None,
        }
    }

    fn exec_cmd(
        cmd: &[String],
        cwd: Option<&str>,
        interactive: bool,
        capture_output: bool,
    ) -> anyhow::Result<Option<String>> {
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

        if capture_output {
            let output = exec_cmd.output()?;
            if !output.status.success() {
                error!("failed to execute docker exec (cmd={:?})", exec_cmd);
                error!("stdout: {}", String::from_utf8_lossy(&output.stdout));
                error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
                anyhow::bail!("failed to execute docker exec");
            }
            Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
        } else {
            let status = exec_cmd
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()?;

            if !status.success() {
                anyhow::bail!("failed to execute docker exec");
            }
            Ok(None)
        }
    }

    fn run_cmd(
        cmd: &[String],
        mount: bool,
        cwd: Option<&str>,
        interactive: bool,
        env: &[String],
        net: bool,
        capture_output: bool,
    ) -> anyhow::Result<Option<String>> {
        let image_tag = Self::get_docker_tag(&DockerContainer::Experiments);
        let mut run_cmd = Command::new("docker");
        run_cmd
            .arg("run")
            .arg("--rm")
            .arg("--name")
            .arg(Self::ACCLESS_DEV_CONTAINER_NAME)
            .arg("--hostname")
            .arg(Self::ACCLESS_DEV_CONTAINER_HOSTNAME);
        if interactive {
            run_cmd.arg("-it");
        }

        run_cmd
            .arg("-e")
            .arg(format!("HOST_UID={}", Self::get_user_id()))
            .arg("-e")
            .arg(format!("HOST_GID={}", Self::get_group_id()));

        if let Some(sevgest_gid) = Self::get_sevguest_group_id() {
            run_cmd.arg("-e").arg(format!("SEV_GID={}", sevgest_gid));
        }

        for e in env {
            run_cmd.arg("-e").arg(e);
        }

        if net {
            run_cmd.arg("--network").arg("host");
        }

        if Path::new("/dev/sev-guest").exists() {
            run_cmd.arg("--device=/dev/sev-guest");
        }

        if Path::new("/dev/tpmrm0").exists() {
            run_cmd.arg("--device=/dev/tpmrm0");
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

        if capture_output {
            let output = run_cmd.output()?;
            if !output.status.success() {
                error!("failed to execute docker run (cmd={run_cmd:?})");
                error!("stdout: {}", String::from_utf8_lossy(&output.stdout));
                error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
                anyhow::bail!("failed to execute docker run");
            }
            Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
        } else {
            let status = run_cmd
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()?;

            if !status.success() {
                error!("failed to execute docker run (cmd={run_cmd:?})");
                anyhow::bail!("failed to execute docker run");
            }
            Ok(None)
        }
    }

    pub fn cli(net: bool) -> anyhow::Result<()> {
        if Self::is_container_running() {
            Self::exec_cmd(&[], Some(DOCKER_ACCLESS_CODE_MOUNT_DIR), true, false)?;
        } else {
            Self::run_cmd(
                &[],
                true,
                Some(DOCKER_ACCLESS_CODE_MOUNT_DIR),
                true,
                &[],
                net,
                false,
            )?;
        }
        Ok(())
    }

    pub fn run(
        cmd: &[String],
        mount: bool,
        cwd: Option<&str>,
        env: &[String],
        net: bool,
        capture_output: bool,
    ) -> anyhow::Result<Option<String>> {
        if Self::is_container_running() {
            if !mount {
                panic!(
                    "Container is already running, but --mount flag was not provided. This is required to ensure code consistency."
                );
            }
            Self::exec_cmd(cmd, cwd, true, capture_output)
        } else {
            Self::run_cmd(cmd, mount, cwd, false, env, net, capture_output)
        }
    }
}

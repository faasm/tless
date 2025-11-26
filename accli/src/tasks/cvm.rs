//! This module implements helper methods to build and run functions inside a
//! cVM image loaded with Accless' code.

use crate::env::Env;
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::{
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::mpsc,
    thread,
    time::Duration,
};

// This timeout needs to be long enough to accomodate for the full VM set-up (in
// the worst case) which involves building all the dependencies inside the cVM.
const CVM_BOOT_TIMEOUT: Duration = Duration::from_secs(240);
const CVM_USER: &str = "ubuntu";
const CVM_ACCLESS_ROOT: &str = "/home/ubuntu/accless";
const EPH_PRIVKEY: &str = "snp-key";
const SSH_PORT: u16 = 2222;

pub fn parse_host_guest_path(s: &str) -> anyhow::Result<(PathBuf, PathBuf)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() == 2 {
        Ok((PathBuf::from(parts[0]), PathBuf::from(parts[1])))
    } else {
        anyhow::bail!("Invalid HOST_PATH:GUEST_PATH format: {}", s)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Component {
    Apt,
    Qemu,
    Ovmf,
    Kernel,
    Disk,
    Keys,
    Cloudinit,
}

impl FromStr for Component {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "apt" => Ok(Component::Apt),
            "qemu" => Ok(Component::Qemu),
            "ovmf" => Ok(Component::Ovmf),
            "kernel" => Ok(Component::Kernel),
            "disk" => Ok(Component::Disk),
            "keys" => Ok(Component::Keys),
            "cloudinit" => Ok(Component::Cloudinit),
            _ => anyhow::bail!("Invalid component: {}", s),
        }
    }
}

impl std::fmt::Display for Component {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Component::Apt => write!(f, "apt"),
            Component::Qemu => write!(f, "qemu"),
            Component::Ovmf => write!(f, "ovmf"),
            Component::Kernel => write!(f, "kernel"),
            Component::Disk => write!(f, "disk"),
            Component::Keys => write!(f, "keys"),
            Component::Cloudinit => write!(f, "cloudinit"),
        }
    }
}

struct QemuGuard {
    child: Child,
}

impl Drop for QemuGuard {
    fn drop(&mut self) {
        info!("Killing QEMU process with PID: {}", self.child.id());
        if let Err(e) = self.child.kill() {
            error!("Failed to kill QEMU process: {}", e);
        }
    }
}

fn snp_root() -> PathBuf {
    let mut path = Env::proj_root();
    path.push("scripts");
    path.push("snp");
    path
}

fn snp_output_dir() -> PathBuf {
    let mut path = snp_root();
    path.push("output");
    path
}

/// Remap a host path to a path in the cVM.
///
/// This function takes a host path that must be within Accless' root, and
/// generates the same path inside the cVM's root filesystem.
pub fn remap_to_cvm_path(host_path: &Path) -> Result<PathBuf> {
    let absolute_host_path = if host_path.is_absolute() {
        host_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(host_path)
    };
    let absolute_host_path = absolute_host_path.canonicalize().map_err(|e| {
        let reason = format!(
            "error canonicalizing path (path={}, error={})",
            host_path.display(),
            e
        );
        error!("remap_to_cvm_path(): {reason}");
        anyhow::anyhow!(reason)
    })?;

    let proj_root = Env::proj_root();
    if absolute_host_path.starts_with(&proj_root) {
        let relative_path = absolute_host_path.strip_prefix(&proj_root).unwrap();
        let cvm_path = Path::new(CVM_ACCLESS_ROOT).join(relative_path);
        Ok(cvm_path)
    } else {
        let reason = format!(
            "path is outside the project root directory (path={}, root={})",
            absolute_host_path.display(),
            proj_root.display()
        );
        error!("remap_to_cvm_path(): {reason}");
        anyhow::bail!(reason);
    }
}

/// Helper method to read the logs from the cVM's stdout until it is ready.
fn wait_for_cvm_ready<R: Read + Send + Sync + 'static>(reader: R, timeout: Duration) -> Result<()> {
    let mut reader = BufReader::new(reader);
    let (tx, rx) = mpsc::channel::<()>();

    thread::spawn(move || {
        let tx = tx;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // EOF
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim_end();
                    // Optional: forward QEMU output to your logs
                    debug!("wait_for_cvm_ready(): [cVM] {trimmed}");

                    // Look for your ready marker; keep it loose so version etc. don't matter
                    if trimmed.contains("cloud-init")
                        && trimmed.contains("Accless SNP test instance")
                        && trimmed.contains("ready")
                    {
                        let _ = tx.send(());
                        break;
                    }
                }
                Err(e) => {
                    warn!("Error reading cVM stdout: {e}");
                    break;
                }
            }
        }
    });

    match rx.recv_timeout(timeout) {
        Ok(()) => Ok(()),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            anyhow::bail!("timed out waiting for cVM to become ready")
        }
        Err(e) => anyhow::bail!("cVM stdout reader terminated unexpectedly (error={e})"),
    }
}

pub fn build(clean: bool, component: Option<Component>) -> Result<()> {
    info!("build(): building cVM image...");
    let mut cmd = Command::new(format!("{}/setup.sh", snp_root().display()));
    cmd.current_dir(Env::proj_root());

    if clean {
        cmd.arg("--clean");
    }

    if let Some(component) = component {
        cmd.arg("--component").arg(format!("{}", component));
    }

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Failed to build cVM image");
    }

    Ok(())
}

/// Run a command inside a cVM.
///
/// Runs a command inside a confidential VM (cVM) after optionally copying files
/// to it. This function first starts the cVM, waits for it to become ready,
/// then SCPs any specified files, and finally executes the given command via
/// SSH.
///
/// # Arguments
///
/// - `cmd`: A slice of strings representing the command and its arguments to be
///   executed inside the cVM.
/// - `scp_files`: An optional slice of `(HostPath, GuestPath)` tuples.
///   `HostPath` is the path to the file on the host machine, and `GuestPath` is
///   the relative path inside the cVM. The `GuestPath` will automatically be
///   prefixed with `/home/ubuntu/accless`.
///
/// # Returns
///
/// A `Result` indicating success or failure.
///
/// # Example Usage
///
/// ```rust,no_run
/// use accli::tasks::cvm;
/// use anyhow::Result;
/// use std::path::PathBuf;
///
/// // Example of running a command without SCPing files
/// cvm::run(&["ls".to_string(), "-la".to_string()], None, None).unwrap();
///
/// // Example of SCPing a file and then running a command
/// let host_path = PathBuf::from("./my_local_file.txt");
/// let guest_path = PathBuf::from("my_remote_file.txt");
/// cvm::run(
///     &["cat".to_string(), "my_remote_file.txt".to_string()],
///     Some(&[(host_path, guest_path)]),
///     None,
/// )
/// .unwrap();
/// ```
/// - `cwd`: An optional `PathBuf` representing the working directory inside the
///   cVM, relative to `/home/ubuntu/accless`. If provided, the command will be
///   executed in this directory.
pub fn run(
    cmd: &[String],
    scp_files: Option<&[(PathBuf, PathBuf)]>,
    cwd: Option<&PathBuf>,
) -> Result<()> {
    // Start QEMU and capture stdout.
    info!("run(): starting cVM...");
    let mut qemu_child = Command::new(format!("{}/run.sh", snp_root().display()))
        .current_dir(Env::proj_root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("run(): failed to spawn QEMU")?;

    let qemu_stdout = qemu_child
        .stdout
        .take()
        .context("run(): failed to capture QEMU stdout")?;

    let _qemu_guard = QemuGuard { child: qemu_child };

    // Wait for cloud-init to signal readiness.
    info!("run(): waiting for cVM to become ready");
    wait_for_cvm_ready(qemu_stdout, CVM_BOOT_TIMEOUT)?;

    // SCP files into the cVM, if any.
    if let Some(files) = scp_files {
        info!("run(): copying files into cVM...");
        for (host_path, guest_path) in files {
            let full_guest_path = format!("{}/{}", CVM_ACCLESS_ROOT, guest_path.display());
            info!(
                "run(): copying {} to {CVM_USER}@localhost:{}",
                host_path.display(),
                full_guest_path
            );

            let mut scp_cmd = Command::new("scp");
            scp_cmd
                .arg("-P")
                .arg(SSH_PORT.to_string())
                .arg("-i")
                .arg(format!("{}/{EPH_PRIVKEY}", snp_output_dir().display()))
                .arg("-o")
                .arg("StrictHostKeyChecking=no")
                .arg("-o")
                .arg("UserKnownHostsFile=/dev/null")
                .arg(host_path)
                .arg(format!("{CVM_USER}@localhost:{}", full_guest_path));

            let status = scp_cmd.status()?;
            if !status.success() {
                anyhow::bail!(
                    "run(): failed to copy file {} to cVM (exit_code={})",
                    host_path.display(),
                    status.code().unwrap_or_default()
                );
            }
        }
    }

    // Construct the command to run in the cVM, including `cd` if `cwd` is
    // specified.
    let mut final_cmd: Vec<String> = Vec::new();
    final_cmd.push("cd".to_string());
    if let Some(cwd_path) = cwd {
        final_cmd.push(format!("{}/{}", CVM_ACCLESS_ROOT, cwd_path.display()));
    } else {
        final_cmd.push(CVM_ACCLESS_ROOT.to_string());
    }
    final_cmd.push("&&".to_string());
    final_cmd.extend_from_slice(cmd);

    info!(
        "run(): running command in cVM (cmd='{}')",
        final_cmd.join(" ")
    );
    let mut ssh_cmd = Command::new("ssh");
    ssh_cmd
        .arg("-p")
        .arg(SSH_PORT.to_string())
        .arg("-i")
        .arg(format!("{}/{EPH_PRIVKEY}", snp_output_dir().display()))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg(format!("{CVM_USER}@localhost"))
        .args(final_cmd);

    let status = ssh_cmd.status()?;
    if !status.success() {
        anyhow::bail!("run(): command failed to execute in cVM");
    }

    Ok(())
}

pub fn cli(cwd: Option<&PathBuf>) -> Result<()> {
    info!("cli(): starting cVM and opening interactive shell...");

    let mut qemu_child = Command::new(format!("{}/run.sh", snp_root().display()))
        .current_dir(Env::proj_root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("cli(): failed to spawn QEMU")?;

    let qemu_stdout = qemu_child
        .stdout
        .take()
        .context("cli(): failed to capture QEMU stdout")?;

    let _qemu_guard = QemuGuard { child: qemu_child };

    info!("cli(): waiting for cVM to become ready");
    wait_for_cvm_ready(qemu_stdout, CVM_BOOT_TIMEOUT)?;

    // Construct the command to run in the cVM (cd into cwd if provided).
    let mut interactive_cmd: Vec<String> = Vec::new();
    if let Some(cwd_path) = cwd {
        interactive_cmd.push("cd".to_string());
        interactive_cmd.push(format!("{}/{}", CVM_ACCLESS_ROOT, cwd_path.display()));
        interactive_cmd.push("&&".to_string());
    }
    interactive_cmd.push("bash".to_string()); // Start a bash shell

    info!("cli(): opening interactive SSH session to cVM");
    let status = Command::new("ssh")
        .arg("-p")
        .arg(SSH_PORT.to_string())
        .arg("-i")
        .arg(format!("{}/{EPH_PRIVKEY}", snp_output_dir().display()))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-t") // Allocate a pseudo-terminal
        .arg(format!("{CVM_USER}@localhost"))
        .args(interactive_cmd)
        .status()?;

    if !status.success() {
        anyhow::bail!("cli(): interactive SSH session failed");
    }

    Ok(())
}

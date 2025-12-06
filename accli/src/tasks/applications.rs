use crate::tasks::{
    cvm,
    docker::{DOCKER_ACCLESS_CODE_MOUNT_DIR, Docker},
};
use anyhow::Result;
use clap::ValueEnum;
use log::error;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone, Debug, ValueEnum)]
pub enum ApplicationBackend {
    Cvm,
    Docker,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum ApplicationType {
    Function,
    Test,
}

impl Display for ApplicationType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ApplicationType::Function => write!(f, "function"),
            ApplicationType::Test => write!(f, "test"),
        }
    }
}

impl FromStr for ApplicationType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "function" => Ok(ApplicationType::Function),
            _ => anyhow::bail!("Invalid ApplicationType: {}", s),
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum ApplicationName {
    #[value(name = "att-client-sgx")]
    AttClientSgx,
    #[value(name = "att-client-snp")]
    AttClientSnp,
    #[value(name = "breakdown-snp")]
    BreakdownSnp,
    #[value(name = "escrow-xput")]
    EscrowXput,
    #[value(name = "hello-snp")]
    HelloSnp,
    #[value(name = "multi-as")]
    MultiAs,
}

impl Display for ApplicationName {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ApplicationName::AttClientSgx => write!(f, "att-client-sgx"),
            ApplicationName::AttClientSnp => write!(f, "att-client-snp"),
            ApplicationName::BreakdownSnp => write!(f, "breakdown-snp"),
            ApplicationName::EscrowXput => write!(f, "escrow-xput"),
            ApplicationName::HelloSnp => write!(f, "hello-snp"),
            ApplicationName::MultiAs => write!(f, "multi-as"),
        }
    }
}

impl FromStr for ApplicationName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "att-client-sgx" => Ok(ApplicationName::AttClientSgx),
            "att-client-snp" => Ok(ApplicationName::AttClientSnp),
            "breakdown-snp" => Ok(ApplicationName::BreakdownSnp),
            "escrow-xput" => Ok(ApplicationName::EscrowXput),
            "hello-snp" => Ok(ApplicationName::HelloSnp),
            "multi-as" => Ok(ApplicationName::MultiAs),
            _ => anyhow::bail!("Invalid Function: {}", s),
        }
    }
}

pub fn host_cert_dir_to_target_path(
    as_cert_dir: &Path,
    backend: &ApplicationBackend,
) -> Result<PathBuf> {
    if !as_cert_dir.exists() {
        let reason = format!(
            "as certificate directory does not exist (path={})",
            as_cert_dir.display()
        );
        error!("host_cert_dir_to_target_path(): {reason}");
        anyhow::bail!(reason);
    }

    if !as_cert_dir.is_dir() {
        let reason = format!(
            "as certificate path does not point to a directory (path={})",
            as_cert_dir.display()
        );
        error!("host_cert_dir_to_target_path(): {reason}");
        anyhow::bail!(reason);
    }

    if as_cert_dir.read_dir()?.next().is_none() {
        let reason = format!(
            "passed --cert-dir variable points to an empty directory: {}",
            as_cert_dir.display()
        );
        error!("host_cert_dir_to_target_path(): {reason}");
        anyhow::bail!(reason);
    }

    match backend {
        ApplicationBackend::Cvm => Ok(cvm::remap_to_cvm_path(as_cert_dir)?),
        ApplicationBackend::Docker => Ok(Docker::remap_to_docker_path(as_cert_dir)?),
    }
}

#[derive(Debug)]
pub struct Applications {}

impl Applications {
    pub fn build(
        clean: bool,
        debug: bool,
        as_cert_dir: Option<PathBuf>,
        capture_output: bool,
        in_cvm: bool,
    ) -> Result<Option<String>> {
        // If --in-cvm flag is passed, we literally re run the same `accli` command, but
        // inside the cVM.
        let mut cmd = if in_cvm {
            vec![
                "./scripts/accli_wrapper.sh".to_string(),
                "applications".to_string(),
                "build".to_string(),
            ]
        } else {
            vec!["python3".to_string(), "build.py".to_string()]
        };

        if clean {
            cmd.push("--clean".to_string());
        }
        if debug {
            cmd.push("--debug".to_string());
        }

        // Work-out the right cert path depending on whether we are gonna SSH into the
        // cVM or not.
        if in_cvm {
            // Make sure the certificates are available in the cVM.
            let mut scp_files: Vec<(PathBuf, PathBuf)> = vec![];
            if let Some(host_cert_dir) = as_cert_dir {
                let guest_cert_dir =
                    host_cert_dir_to_target_path(&host_cert_dir, &ApplicationBackend::Cvm)?;
                scp_files.push((host_cert_dir, guest_cert_dir.clone()));

                cmd.push("--as-cert-dir".to_string());
                cmd.push(guest_cert_dir.display().to_string());
            }

            cvm::run(
                &cmd,
                if scp_files.is_empty() {
                    None
                } else {
                    Some(&scp_files)
                },
                None,
            )?;
            Ok(None)
        } else {
            if let Some(host_cert_dir) = as_cert_dir {
                let docker_cert_dir =
                    host_cert_dir_to_target_path(&host_cert_dir, &ApplicationBackend::Docker)?;
                cmd.push("--as-cert-dir".to_string());
                cmd.push(docker_cert_dir.display().to_string());
            }
            let workdir = Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR).join("applications");
            let workdir_str = workdir.to_str().ok_or_else(|| {
                anyhow::anyhow!("Workdir path is not valid UTF-8: {}", workdir.display())
            })?;
            Docker::run(
                &cmd,
                true,
                Some(workdir_str),
                &[],
                false,
                capture_output,
                None,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        app_type: &ApplicationType,
        app_name: &ApplicationName,
        app_backend: &ApplicationBackend,
        run_as_root: bool,
        extra_docker_flags: Option<&[&str]>,
        args: Vec<String>,
    ) -> anyhow::Result<Option<String>> {
        match app_backend {
            // If --in-cvm flag is passed, we literally re run the same `accli` command, but
            // inside the cVM.
            ApplicationBackend::Cvm => {
                let mut cmd = vec![
                    "./scripts/accli_wrapper.sh".to_string(),
                    "applications".to_string(),
                    "run".to_string(),
                    format!("{app_type}"),
                    format!("{app_name}"),
                ];

                if run_as_root {
                    cmd.push("--run-as-root".to_string());
                }

                if !args.is_empty() {
                    cmd.push("--".to_string());
                    cmd.extend(args);
                }

                // We don't need to SCP any files here, because we assume that the certificates
                // have been copied during the build stage, and persisted in the
                // disk image.
                cvm::run(&cmd, None, None)?;

                Ok(None)
            }
            ApplicationBackend::Docker => {
                let dir_name = match app_type {
                    ApplicationType::Function => "functions",
                    ApplicationType::Test => "test",
                };
                // Path matches CMake build directory:
                // ./applications/build-natie/{functions,test,workflows}/{name}/{binary_name}
                let binary_path = Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR)
                    .join("applications/build-native")
                    .join(dir_name)
                    .join(format!("{app_name}"))
                    .join(format!("{app_name}"));

                let binary_path_str = binary_path.to_str().ok_or_else(|| {
                    let reason = format!(
                        "binary path is not valid UTF-8 (path={})",
                        binary_path.display()
                    );
                    error!("run(): {reason}");
                    anyhow::anyhow!(reason)
                })?;
                let mut cmd = if run_as_root {
                    vec!["sudo".to_string(), binary_path_str.to_string()]
                } else {
                    vec![binary_path_str.to_string()]
                };
                cmd.extend(args);

                Docker::run(&cmd, true, None, &[], true, false, extra_docker_flags)
            }
        }
    }
}

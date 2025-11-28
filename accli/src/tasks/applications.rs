use crate::tasks::{
    attestation_service, cvm,
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
}

impl Display for ApplicationName {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ApplicationName::AttClientSgx => write!(f, "att-client-sgx"),
            ApplicationName::AttClientSnp => write!(f, "att-client-snp"),
            ApplicationName::BreakdownSnp => write!(f, "breakdown-snp"),
            ApplicationName::EscrowXput => write!(f, "escrow-xput"),
            ApplicationName::HelloSnp => write!(f, "hello-snp"),
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
            _ => anyhow::bail!("Invalid Function: {}", s),
        }
    }
}

fn host_cert_path_to_target_path(
    as_cert_path: &Path,
    in_cvm: bool,
    in_docker: bool,
) -> Result<PathBuf> {
    if in_cvm & in_docker {
        let reason = "cannot set in_cvm and in_docker";
        error!("as_cert_path_arg_to_real_path(): {reason}");
        anyhow::bail!(reason);
    }

    if !as_cert_path.exists() {
        let reason = format!(
            "as certificate path does not exist (path={})",
            as_cert_path.display()
        );
        error!("as_cert_path_arg_to_real_path(): {reason}");
        anyhow::bail!(reason);
    }

    if !as_cert_path.is_file() {
        let reason = format!(
            "as certificate path does not point to a file (path={})",
            as_cert_path.display()
        );
        error!("as_cert_path_arg_to_real_path(): {reason}");
        anyhow::bail!(reason);
    }

    if in_docker {
        Ok(Docker::remap_to_docker_path(as_cert_path)?)
    } else if in_cvm {
        Ok(cvm::remap_to_cvm_path(as_cert_path)?)
    } else {
        Ok(as_cert_path.to_path_buf())
    }
}

#[derive(Debug)]
pub struct Applications {}

impl Applications {
    pub fn build(
        clean: bool,
        debug: bool,
        as_cert_path: Option<PathBuf>,
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
            if let Some(host_cert_path) = as_cert_path {
                let guest_cert_path = host_cert_path_to_target_path(&host_cert_path, true, false)?;
                scp_files.push((host_cert_path, guest_cert_path.clone()));

                cmd.push("--as-cert-path".to_string());
                cmd.push(guest_cert_path.display().to_string());
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
            if let Some(host_cert_path) = as_cert_path {
                let docker_cert_path = host_cert_path_to_target_path(&host_cert_path, false, true)?;
                cmd.push("--as-cert-path".to_string());
                cmd.push(docker_cert_path.display().to_string());
            }
            let workdir = Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR).join("applications");
            let workdir_str = workdir.to_str().ok_or_else(|| {
                anyhow::anyhow!("Workdir path is not valid UTF-8: {}", workdir.display())
            })?;
            Docker::run(&cmd, true, Some(workdir_str), &[], false, capture_output)
        }
    }

    pub fn run(
        app_type: ApplicationType,
        app_name: ApplicationName,
        in_cvm: bool,
        as_url: Option<String>,
        as_cert_path: Option<PathBuf>,
    ) -> anyhow::Result<Option<String>> {
        // If --in-cvm flag is passed, we literally re run the same `accli` command, but
        // inside the cVM.
        if in_cvm {
            let mut cmd = vec![
                "./scripts/accli_wrapper.sh".to_string(),
                "applications".to_string(),
                "run".to_string(),
                format!("{app_type}"),
                format!("{app_name}"),
            ];

            if let Some(as_url) = as_url {
                cmd.push("--as-url".to_string());
                cmd.push(as_url.to_string());
            }

            if let Some(host_cert_path) = as_cert_path {
                cmd.push("--as-cert-path".to_string());
                cmd.push(
                    host_cert_path_to_target_path(&host_cert_path, true, false)?
                        .display()
                        .to_string(),
                );
            }

            // We don't need to SCP any files here, because we assume that the certificates
            // have been copied during the build stage, and persisted in the
            // disk image.
            cvm::run(&cmd, None, None)?;

            Ok(None)
        } else {
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
                anyhow::anyhow!("Binary path is not valid UTF-8: {}", binary_path.display())
            })?;
            let cmd = vec![binary_path_str.to_string()];

            let as_env_vars: Vec<String> = match (as_url, as_cert_path) {
                (Some(as_url), Some(host_cert_path)) => {
                    let docker_cert_path =
                        host_cert_path_to_target_path(&host_cert_path, false, true)?
                            .display()
                            .to_string();
                    attestation_service::get_as_env_vars(&as_url, &docker_cert_path)
                }
                _ => vec![],
            };

            Docker::run(&cmd, true, None, &as_env_vars, true, false)
        }
    }
}

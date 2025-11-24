use crate::tasks::{
    attestation_service, cvm,
    docker::{DOCKER_ACCLESS_CODE_MOUNT_DIR, Docker},
};
use anyhow::{Context, Result};
use clap::ValueEnum;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone, Debug, ValueEnum)]
pub enum ApplicationType {
    Function,
}

impl Display for ApplicationType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ApplicationType::Function => write!(f, "function"),
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
pub enum Functions {
    #[value(name = "escrow-xput")]
    EscrowXput,
}

impl Display for Functions {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Functions::EscrowXput => write!(f, "escrow-xput"),
        }
    }
}

impl FromStr for Functions {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "escrow-xput" => Ok(Functions::EscrowXput),
            _ => anyhow::bail!("Invalid Function: {}", s),
        }
    }
}

#[derive(Debug)]
pub struct Applications {}

impl Applications {
    pub fn build(
        clean: bool,
        debug: bool,
        cert_path: Option<&str>,
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

        if in_cvm {
            // Make sure the certificates are available in the cVM.
            let mut scp_files: Vec<(PathBuf, PathBuf)> = vec![];
            if let Some(cert_path_str) = cert_path {
                let host_cert_path = PathBuf::from(cert_path_str);
                if !host_cert_path.exists() {
                    anyhow::bail!(
                        "Certificate path does not exist: {}",
                        host_cert_path.display()
                    );
                }
                if !host_cert_path.is_file() {
                    anyhow::bail!(
                        "Certificate path is not a file: {}",
                        host_cert_path.display()
                    );
                }
                let guest_cert_path = PathBuf::from("applications").join(
                    host_cert_path
                        .file_name()
                        .context("Failed to get file name for cert path")?,
                );
                scp_files.push((host_cert_path, guest_cert_path.clone()));

                cmd.push("--cert-path".to_string());
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

    pub fn run(
        app_type: ApplicationType,
        app_name: Functions,
        in_cvm: bool,
        as_url: Option<String>,
        as_cert_path: Option<PathBuf>,
    ) -> anyhow::Result<Option<String>> {
        let binary_name = match app_name {
            Functions::EscrowXput => "escrow-xput",
        };

        // If --in-cvm flag is passed, we literally re run the same `accli` command, but
        // inside the cVM.
        if in_cvm {
            let cmd = vec![
                "./scripts/accli_wrapper.sh".to_string(),
                "applications".to_string(),
                "run".to_string(),
                format!("{app_type}"),
                format!("{app_name}"),
            ];

            // We don't need to SCP any files here, because we assume that the certificates
            // have been copied during the build stage, and persisted in the
            // disk image.
            cvm::run(&cmd, None, None)?;

            Ok(None)
        } else {
            let binary_path = match app_type {
                ApplicationType::Function => Path::new(DOCKER_ACCLESS_CODE_MOUNT_DIR)
                    .join("applications/build-native")
                    .join(binary_name)
                    .join(binary_name),
            };

            let binary_path_str = binary_path.to_str().ok_or_else(|| {
                anyhow::anyhow!("Binary path is not valid UTF-8: {}", binary_path.display())
            })?;
            let cmd = vec![binary_path_str.to_string()];

            let as_env_vars: Vec<String> = match (as_url, as_cert_path) {
                (Some(as_url), Some(as_cert_path)) => attestation_service::get_as_env_vars(
                    &as_url,
                    as_cert_path.to_str().ok_or_else(|| {
                        anyhow::anyhow!(
                            "as cert path is not valid UTF-8 (path={})",
                            as_cert_path.display()
                        )
                    })?,
                ),
                _ => vec![],
            };

            Docker::run(&cmd, true, None, &as_env_vars, false, false)
        }
    }
}

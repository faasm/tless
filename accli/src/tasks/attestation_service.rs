use crate::env::Env;
use anyhow::Result;
use log::info;
use reqwest;
use std::{
    fs,
    process::{Command, Stdio},
};

pub struct AttestationService;

impl AttestationService {
    pub fn build() -> Result<()> {
        let mut cmd = Command::new("cargo");
        cmd.arg("build")
            .arg("-p")
            .arg("attestation-service")
            .arg("--release");
        let status = cmd.status()?;
        if !status.success() {
            anyhow::bail!("Failed to build attestation service");
        }
        Ok(())
    }

    pub fn run(
        certs_dir: Option<&std::path::Path>,
        port: Option<u16>,
        sgx_pccs_url: Option<&std::path::Path>,
        force_clean_certs: bool,
        mock: bool,
        rebuild: bool,
    ) -> Result<()> {
        if rebuild {
            Self::build()?;
        }

        let mut cmd = Command::new(
            Env::proj_root()
                .join("target")
                .join("release")
                .join("attestation-service"),
        );
        if let Some(certs_dir) = certs_dir {
            cmd.arg("--certs-dir").arg(certs_dir);
        }
        if let Some(port) = port {
            cmd.arg("--port").arg(port.to_string());
        }
        if let Some(sgx_pccs_url) = sgx_pccs_url {
            cmd.arg("--sgx-pccs-url").arg(sgx_pccs_url);
        }
        if force_clean_certs {
            cmd.arg("--force-clean-certs");
        }
        if mock {
            cmd.arg("--mock");
        }
        let status = cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        if !status.success() {
            anyhow::bail!("Failed to run attestation service");
        }
        Ok(())
    }

    pub async fn health(url: Option<String>, cert_path: Option<std::path::PathBuf>) -> Result<()> {
        let url = url.or_else(|| std::env::var("ACCLESS_AS_URL").ok());
        let cert_path = cert_path.or_else(|| {
            std::env::var("ACCLESS_AS_CERT_PATH")
                .ok()
                .map(std::path::PathBuf::from)
        });

        let url = match url {
            Some(url) => url,
            None => {
                anyhow::bail!("Attestation service URL not provided. Set --url or ACCLESS_AS_URL")
            }
        };

        let client = match cert_path {
            Some(cert_path) => {
                let cert = fs::read(cert_path)?;
                let cert = reqwest::Certificate::from_pem(&cert)?;
                reqwest::Client::builder()
                    .add_root_certificate(cert)
                    .build()
            }
            None => reqwest::Client::builder().build(),
        }?;

        let response = client.get(format!("{}/health", url)).send().await?;
        info!("Health check response: {}", response.text().await?);

        Ok(())
    }
}

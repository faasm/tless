use crate::state::AttestationServiceState;
use anyhow::Result;
use axum::{
    Extension, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;
use hyper::server::conn::http1;
use hyper_util::{rt::tokio::TokioIo, service::TowerToHyperService};
use log::{error, info};
use rustls::crypto::CryptoProvider;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;

#[cfg(feature = "snp")]
mod amd;
#[cfg(feature = "azure-cvm")]
mod azure_cvm;
mod ecdhe;
#[cfg(feature = "sgx")]
mod intel;
mod jwt;
mod mock;
mod request;
#[cfg(feature = "sgx")]
mod sgx;
#[cfg(feature = "snp")]
mod snp;
mod state;
mod tls;
mod types;

const DEFAULT_PORT: u16 = 8443;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Directory where to look-for and store TLS certificates.
    #[arg(long)]
    certs_dir: Option<PathBuf>,
    /// Port to bind the server to.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// URL to fetch SGX platform collateral information.
    #[arg(long)]
    sgx_pccs_url: Option<PathBuf>,
    /// Whether to overwrite the existing TLS certificates (if any).
    #[arg(long)]
    force_clean_certs: bool,
    /// Run the attestation service in mock mode, skipping quote verification.
    #[arg(long, default_value_t = false)]
    mock: bool,
    /// Overwrite the public IP of the attestation service.
    #[arg(long)]
    overwrite_external_ip: Option<String>,
}

async fn health(Extension(state): Extension<Arc<AttestationServiceState>>) -> impl IntoResponse {
    (StatusCode::OK, state.external_url.clone())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise logging and parse CLI arguments.
    let cli = Cli::parse();
    attestation_service::init_logging();

    // Initialise crypto provider and TLS config, this also sets up the TLS
    // certificates if necessary.
    CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .map_err(|e| anyhow::anyhow!("error initializing rustls provider (error={e:?})"))?;
    let external_ip = match cli.overwrite_external_ip {
        Some(ip) => ip,
        None => tls::get_node_url()?,
    };
    let tls_acceptor =
        tls::load_config(cli.certs_dir.clone(), cli.force_clean_certs, &external_ip).await?;
    let external_url = format!("https://{}:{}", external_ip, cli.port);

    // Set-up per request state.
    let state = Arc::new(AttestationServiceState::new(
        cli.certs_dir.clone(),
        cli.sgx_pccs_url.clone(),
        cli.mock,
        external_url.clone(),
    )?);

    // Start HTTPS server.
    let app = Router::new()
        .route("/health", get(health))
        .route("/state", get(request::get_state))
        .route("/verify-sgx-report", post(sgx::verify_sgx_report))
        .route("/verify-snp-report", post(snp::verify_snp_report))
        .route(
            "/verify-snp-vtpm-report",
            post(azure_cvm::verify_snp_vtpm_report),
        )
        .layer(Extension(state.clone()));
    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    let listener = TcpListener::bind(addr).await;

    info!("main(): accless attestation server running!");
    info!("main(): external IP: {}", external_url);
    info!(
        "main(): cert path: {}/cert.pem",
        cli.certs_dir
            .unwrap_or(tls::get_default_certs_dir())
            .display()
    );

    loop {
        let (stream, _) = listener.as_ref().expect("error listening").accept().await?;
        let service = TowerToHyperService::new(app.clone());
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        error!("as: connection error: {:?}", err);
                    }
                }
                Err(err) => error!("as: TLS handshake failed: {:?}", err),
            }
        });
    }
}

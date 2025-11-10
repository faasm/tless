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

#[cfg(feature = "azure-cvm")]
mod azure_cvm;
#[cfg(feature = "sgx")]
mod intel;
mod jwt;
mod request;
#[cfg(feature = "sgx")]
mod sgx;
#[cfg(feature = "snp")]
mod snp;
mod state;
mod tls;

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
    /// Run the SGX handler in mock mode, skipping quote verification.
    #[arg(long, default_value_t = false)]
    mock_sgx: bool,
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

fn init_logger() {
    env_logger::init_from_env(
        env_logger::Env::default().default_filter_or("error,attestation_service=info"),
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise logging and parse CLI arguments.
    init_logger();
    let cli = Cli::parse();

    // Initialise crypto provider and TLS config, this also sets up the TLS
    // certificates if necessary.
    CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .map_err(|e| anyhow::anyhow!("error initializing rustls provider (error={e:?})"))?;
    let tls_acceptor = tls::load_config(cli.certs_dir.clone(), cli.force_clean_certs).await?;

    // Set-up per request state.
    let state = Arc::new(AttestationServiceState::new(
        cli.certs_dir,
        cli.sgx_pccs_url.clone(),
        cli.mock_sgx,
    )?);

    // Start HTTPS server.
    let app = Router::new()
        .route("/health", get(health))
        .route("/verify-sgx-report", post(sgx::verify_sgx_report))
        .route("/verify-snp-report", post(snp::verify_snp_report))
        .layer(Extension(state.clone()));
    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    let listener = TcpListener::bind(addr).await;

    info!("Accless attestation server running on https://{}", addr);
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

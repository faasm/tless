use crate::state::AttestationServiceState;
use anyhow::Result;
use axum::{Extension, Router, routing::post};
use hyper::server::conn::http1;
use hyper_util::{rt::tokio::TokioIo, service::TowerToHyperService};
use log::info;
use rustls::crypto::CryptoProvider;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

#[cfg(feature = "azure-cvm")]
mod azure_cvm;
mod jwt;
#[cfg(feature = "sgx")]
mod sgx;
#[cfg(feature = "snp")]
mod snp;
mod state;
mod tls;

#[tokio::main]
async fn main() -> Result<()> {
    let state = Arc::new(AttestationServiceState::new());
    CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .map_err(|e| anyhow::anyhow!("error initializing rustls provider (error={e:?})"))?;

    let app = Router::new()
        .route("/verify-sgx-report", post(sgx::verify_sgx_report))
        .route("/verify-snp-report", post(snp::verify_snp_report))
        .layer(Extension(state.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    let tls_acceptor = tls::load_config(false).await?;
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
                        eprintln!("as: connection error: {:?}", err);
                    }
                }
                Err(err) => eprintln!("as: TLS handshake failed: {:?}", err),
            }
        });
    }
}

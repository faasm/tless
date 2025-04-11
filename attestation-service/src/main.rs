use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use hyper::server::conn::http1;
use hyper_util::{rt::tokio::TokioIo, service::TowerToHyperService};
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::Deserialize;
use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VcekResponse {
    vcek_cert: String,
    certificate_chain: String,
}

pub fn fetch_vcek_pem() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let resp: VcekResponse = ureq::get("http://169.254.169.254/metadata/THIM/amd/certification")
        .set("Metadata", "true")
        .call()?
        .into_json()?;

    let pem = format!("{}\n{}", resp.vcek_cert, resp.certificate_chain);
    Ok(pem.into_bytes())
}

#[derive(Clone, Debug)]
struct AppState {
    pub vcek_pem: Vec<u8>,
}

async fn load_tls_config() -> anyhow::Result<TlsAcceptor> {
    let cert_file = &mut BufReader::new(File::open("certs/cert.pem")?);
    let key_file = &mut BufReader::new(File::open("certs/key.pem")?);

    let cert_chain: Vec<CertificateDer> = certs(cert_file)?
        .into_iter()
        .map(CertificateDer::from)
        .collect();

    let mut keys = pkcs8_private_keys(key_file)?;
    if keys.is_empty() {
        anyhow::bail!("accless: 0 private keys found in PEM");
    }
    let raw_key = keys.remove(0);
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(raw_key));

    let config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Preload or generate your state
    let vcek_pem = fetch_vcek_pem();
    let state = Arc::new(AppState {
        vcek_pem: vcek_pem.expect("as: failed to get vceck"),
    });

    CryptoProvider::install_default(rustls::crypto::ring::default_provider()).unwrap();

    let app = Router::new()
        .route("/verify-snp-report", post(verify_snp_report))
        .layer(Extension(state.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    let tls_acceptor = load_tls_config().await?;
    let listener = TcpListener::bind(addr).await;
    println!("Server running on https://{}", addr);

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

async fn verify_snp_report(
    Extension(state): Extension<Arc<AppState>>,
    body: Body,
) -> impl IntoResponse {
    // Convert raw body to Bytes
    let full_body = to_bytes(body, 1024 * 1024).await;

    match full_body {
        Ok(bytes) => {
            match snpguest::verify::attestation::verify_attestation(&state.vcek_pem, bytes.as_ref())
            {
                Ok(_) => (StatusCode::OK, "attestation report verified"),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERROR: attestation report verification failed",
                ),
            }
        }
        Err(_) => (StatusCode::BAD_REQUEST, "Invalid body".into()),
    }
}

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use hyper::server::conn::http1;
use hyper_util::{rt::tokio::TokioIo, service::TowerToHyperService};
use jsonwebtoken::{EncodingKey, Header, encode};
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// TODO(accless-prod): this two values MUST be secret in a deployment, and
// rotated periodically
static TEE_IDENTITY: &str = "G4Nu1N3_4CCL355";
static TEE_AES_KEY_B64: &str = "2mKTvMZ7uieJFWGYArGrYsqc9DKRIR+xxVHCK13T+bk=";

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
    aud: String,
    tee: String,
    tee_identity: String,
    aes_key_b64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VcekResponse {
    vcek_cert: String,
    certificate_chain: String,
}

/// This method can only be called from an Azure VM
pub fn fetch_vcek_pem() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let resp: VcekResponse = ureq::get("http://169.254.169.254/metadata/THIM/amd/certification")
        .set("Metadata", "true")
        .call()?
        .into_json()?;

    let pem = format!("{}\n{}", resp.vcek_cert, resp.certificate_chain);
    Ok(pem.into_bytes())
}

fn generate_jwt_encoding_key() -> Result<EncodingKey, anyhow::Error> {
    let key_file = &mut BufReader::new(File::open("certs/key.pem")?);
    let mut keys = pkcs8_private_keys(key_file)?;
    if keys.is_empty() {
        anyhow::bail!("accless: 0 private keys found in PEM");
    }
    let raw_key = keys.remove(0);
    let jwt_encoding_key = EncodingKey::from_rsa_der(&raw_key);

    Ok(jwt_encoding_key)
}

#[derive(Clone)]
struct AppState {
    pub vcek_pem: Vec<u8>,
    pub jwt_encoding_key: EncodingKey,
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
        jwt_encoding_key: generate_jwt_encoding_key()?,
    });

    CryptoProvider::install_default(rustls::crypto::ring::default_provider()).unwrap();

    let app = Router::new()
        .route("/verify-sgx-report", post(verify_sgx_report))
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

async fn verify_sgx_report(
    Extension(state): Extension<Arc<AppState>>,
    body: Body,
) -> impl IntoResponse {
    // Convert raw body to Bytes
    let full_body = to_bytes(body, 1024 * 1024).await;

    // TODO: validate SGX quote using DCAP's Quote Verification Library (QVL)
    match full_body {
        Ok(_) => {
            let claims = JwtClaims {
                sub: "attested-client".to_string(),
                exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
                aud: "accless-attestation-service".to_string(),
                tee: "sgx".to_string(),
                // TODO: TEE identity should be a secret
                tee_identity: TEE_IDENTITY.to_string(),
                aes_key_b64: TEE_AES_KEY_B64.to_string(),
            };

            match encode(&Header::default(), &claims, &state.jwt_encoding_key) {
                Ok(token) => (StatusCode::OK, token),
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to encode JWT".into(),
                ),
            }
        }
        Err(_) => (StatusCode::BAD_REQUEST, "Invalid body".into()),
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
                Ok(_) => {
                    let claims = JwtClaims {
                        sub: "attested-client".to_string(),
                        exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp()
                            as usize,
                        aud: "accless-attestation-service".to_string(),
                        tee: "snp".to_string(),
                        // TODO: TEE identity should be a secret
                        tee_identity: TEE_IDENTITY.to_string(),
                        aes_key_b64: TEE_AES_KEY_B64.to_string(),
                    };

                    match encode(&Header::default(), &claims, &state.jwt_encoding_key) {
                        Ok(token) => (StatusCode::OK, token),
                        Err(_) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to encode JWT".into(),
                        ),
                    }
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERROR: attestation report verification failed".into(),
                ),
            }
        }
        Err(_) => (StatusCode::BAD_REQUEST, "Invalid body".into()),
    }
}

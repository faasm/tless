use aes_gcm::aead::{Aead, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axum::{
    Extension, Json, Router,
    body::{Body, to_bytes},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use base64::{Engine as _, engine::general_purpose};
use hyper::server::conn::http1;
use hyper_util::{rt::tokio::TokioIo, service::TowerToHyperService};
use jsonwebtoken::{EncodingKey, Header, encode};
use ring::agreement::{self, ECDH_P256, UnparsedPublicKey};
use ring::rand::SystemRandom;
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// TODO(accless-prod): this two values MUST be secret in a deployment, and
// rotated periodically
static TEE_IDENTITY: &str = "G4Nu1N3_4CCL355";
static TEE_AES_KEY_B64: &str = "2mKTvMZ7uieJFWGYArGrYsqc9DKRIR+xxVHCK13T+bk=";

/// This struct corresponds to the JWT that the attestation service returns
/// irrespective of the incoming TEE that sent the request.
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
    aud: String,
    tee: String,
    tee_identity: String,
    aes_key_b64: String,
}

// ----------------------------------------------------------------------------
// SGX stuff
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InitTimeData {
    _data: String,
    _data_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeData {
    data: String,
    _data_type: String,
}

/// This struct corresponds to the request that SGX-Faasm sends to verify
/// an SGX report. Most importantly, the quote is the actual SGX quote, and
/// the runtime_data corresponds to the enclave held data, which is the public
/// key of the target enclave.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SgxRequest {
    _draft_policy_for_attestation: String,
    _init_time_data: InitTimeData,
    quote: String,
    runtime_data: RuntimeData,
}

// ----------------------------------------------------------------------------
// SNP stuff
// ----------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VcekResponse {
    vcek_cert: String,
    certificate_chain: String,
}

/// This method can only be called from an Azure cVM
pub fn fetch_vcek_pem() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match ureq::get("http://169.254.169.254/metadata/THIM/amd/certification")
        .set("Metadata", "true")
        .call()
    {
        Ok(resp) => match resp.into_json::<VcekResponse>() {
            Ok(data) => {
                let pem = format!("{}\n{}", data.vcek_cert, data.certificate_chain);
                Ok(pem.into_bytes())
            }
            Err(e) => {
                eprintln!("WARNING: failed to parse VCECK response JSON: {e}");
                Ok(vec![])
            }
        },
        Err(e) => {
            eprintln!("WARNING: failed to fetch VCECK certificates: {e}");
            Ok(vec![])
        }
    }
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
    pub aes_key_b64: String,
    pub tee_identity: String,
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
        aes_key_b64: TEE_AES_KEY_B64.to_string(),
        tee_identity: TEE_IDENTITY.to_string(),
    });

    CryptoProvider::install_default(rustls::crypto::ring::default_provider()).unwrap();

    let app = Router::new()
        // TODO(accless-prod): this endpoint is just for debugging purposes,
        // and insecure as it leaks the keys
        .route("/get-keys", axum::routing::get(get_keys))
        .route("/get-tee-identity", axum::routing::get(get_tee_identity))
        .route("/verify-sgx-report", post(verify_sgx_report))
        .route("/verify-snp-report", post(verify_snp_report))
        .layer(Extension(state.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    let tls_acceptor = load_tls_config().await?;
    let listener = TcpListener::bind(addr).await;
    println!("Accless attestation server running on https://{}", addr);

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

async fn get_keys(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    (StatusCode::OK, state.aes_key_b64.clone())
}

async fn get_tee_identity(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    (StatusCode::OK, state.tee_identity.clone())
}

async fn verify_sgx_report(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<SgxRequest>,
) -> impl IntoResponse {
    // Decode the quote
    let _quote_bytes = match general_purpose::STANDARD.decode(&payload.quote) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in quote" })),
            );
        }
    };

    // TODO: validate the quote and check that the runtime data matches the
    // held data in the quote
    // TODO: validate SGX quote using DCAP's Quote Verification Library (QVL)

    // Use the enclave held data (runtime_data) public key, to derive an
    // encryption key to protect the returned JWT, which contains secrets.
    // This is only necessary for SGX, as the HTTPS connection is terminated
    // outside of the enclave.
    let pubkey_bytes = match general_purpose::STANDARD.decode(&payload.runtime_data.data) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in runtimeData.data" })),
            );
        }
    };

    // Parse EC P-256 public key
    let peer_pubkey = UnparsedPublicKey::new(&ECDH_P256, pubkey_bytes);

    // Generate ephemeral private key and do ECDH
    let rng = SystemRandom::new();
    let my_private_key = match agreement::EphemeralPrivateKey::generate(&ECDH_P256, &rng) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "key generation failed" })),
            );
        }
    };

    // Also prepare the public part of the ephemeral key we have used for the
    // key derivation step above
    let server_pub_key = my_private_key.compute_public_key().unwrap();
    let server_pub_b64 = general_purpose::STANDARD.encode(server_pub_key);

    // Now do the key derivation
    let shared_secret: Vec<u8> = match agreement::agree_ephemeral(
        my_private_key,
        &peer_pubkey,
        // (),
        |shared_secret_material| {
            Ok::<Vec<u8>, ring::error::Unspecified>(shared_secret_material.to_vec())
        },
    ) {
        Ok(secret) => secret.unwrap(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "EC key agreement failed" })),
            );
        }
    };

    let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&shared_secret[..32]);
    let cipher = Aes256Gcm::new(aes_key);

    let claims = JwtClaims {
        sub: "attested-client".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize,
        aud: "accless-attestation-service".to_string(),
        tee: "sgx".to_string(),
        tee_identity: state.tee_identity.clone(),
        aes_key_b64: state.aes_key_b64.clone(),
    };

    let jwt = match encode(&Header::default(), &claims, &state.jwt_encoding_key) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "JWT encoding failed" })),
            );
        }
    };

    // Encrypt the JWT
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = match cipher.encrypt(nonce, jwt.as_bytes()) {
        Ok(ct) => ct,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "JWT encryption failed" })),
            );
        }
    };

    // Return base64(nonce + ciphertext) as a JSON payload
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    let encrypted_b64 = general_purpose::STANDARD.encode(&combined);
    let response = json!({ 
        "encrypted_token": encrypted_b64,
        "server_pubkey": server_pub_b64
    });

    (StatusCode::OK, Json(response))
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

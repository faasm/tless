use crate::{jwt::JwtClaims, state::AttestationServiceState};
use aes_gcm::{
    Aes128Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use axum::{Extension, Json, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose};
use log::error;
use p256::PublicKey;
use ring::{
    agreement::{self, ECDH_P256, UnparsedPublicKey},
    rand::SystemRandom,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

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

fn is_valid_p256_point(bytes: &[u8]) -> bool {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return false;
    }
    PublicKey::from_sec1_bytes(bytes).is_ok()
}

/// This struct corresponds to the request that SGX-Faasm sends to verify
/// an SGX report. Most importantly, the quote is the actual SGX quote, and
/// the runtime_data corresponds to the enclave held data, which is the public
/// key of the target enclave.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SgxRequest {
    _draft_policy_for_attestation: String,
    _init_time_data: InitTimeData,
    quote: String,
    runtime_data: RuntimeData,
}

/// SGX's crypto library uses little-endian encoding for the coordinates in
/// the crypto library, whereas Rust's ring uses big-endian. We thus need to
/// convert the raw bytes we receive, as part of the enclave's held data in
/// the report, to big endian
fn sgx_pubkey_to_sec1_format(raw: &[u8]) -> Option<[u8; 65]> {
    if raw.len() != 64 {
        return None;
    }

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;

    // Reverse gx (first 32 bytes)
    for i in 0..32 {
        sec1[1 + i] = raw[31 - i];
    }

    // Reverse gy (next 32 bytes)
    for i in 0..32 {
        sec1[33 + i] = raw[63 - i];
    }

    Some(sec1)
}

/// Reverse the process above: given a SEC1 key usable in Rust, convert it
/// to something we can parse in the SGX SDK
fn sec1_pubkey_to_sgx(sec1_pubkey: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Skip prefix indicatting raw (uncompressed) point
    let gx_be = &sec1_pubkey[1..33];
    let gy_be = &sec1_pubkey[33..65];

    // Big-endian → Little-endian
    let mut gx_le = gx_be.to_vec();
    let mut gy_le = gy_be.to_vec();
    gx_le.reverse();
    gy_le.reverse();

    let mut sgx_le_pubkey = Vec::with_capacity(64);
    sgx_le_pubkey.extend_from_slice(&gx_le);
    sgx_le_pubkey.extend_from_slice(&gy_le);

    Ok(sgx_le_pubkey)
}

pub async fn verify_sgx_report(
    Extension(state): Extension<Arc<AttestationServiceState>>,
    Json(payload): Json<SgxRequest>,
) -> impl IntoResponse {
    // Decode the quote
    // WARNING: we must use URL_SAFE as on the client side we are encoding
    // with cppcodec::base64_url
    let raw_quote_b64 = payload.quote.replace(['\n', '\r'], "");
    let _quote_bytes = match general_purpose::URL_SAFE.decode(&raw_quote_b64) {
        Ok(b) => {
            // TODO: validate the quote and check that the runtime data matches the
            // held data in the quote
            // TODO: validate SGX quote using DCAP's Quote Verification Library (QVL)

            b
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in quote" })),
            );
        }
    };

    // Use the enclave held data (runtime_data) public key, to derive an
    // encryption key to protect the returned JWT, which contains secrets.
    // This is only necessary for SGX, as the HTTPS connection is terminated
    // outside of the enclave.
    // WARNING: we must use URL_SAFE as on the client side we are encoding
    // with cppcodec::base64_url
    let raw_pubkey_bytes = match general_purpose::URL_SAFE.decode(&payload.runtime_data.data) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in runtimeData.data" })),
            );
        }
    };
    let pubkey_bytes = match sgx_pubkey_to_sec1_format(&raw_pubkey_bytes) {
        Some(b) => b,
        None => {
            error!("error converting SGX public key to SEC1 format");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid public key length" })),
            );
        }
    };
    if !is_valid_p256_point(&pubkey_bytes) {
        error!("error validating SGX-provided public key");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid EC public key" })),
        );
    }

    // Parse EC P-256 public key
    let peer_pubkey = UnparsedPublicKey::new(&ECDH_P256, pubkey_bytes);

    // Generate ephemeral private key and do ECDH
    let rng = SystemRandom::new();
    let my_private_key = match agreement::EphemeralPrivateKey::generate(&ECDH_P256, &rng) {
        Ok(k) => k,
        Err(e) => {
            error!("error generating ECDH private key (error={e:?})");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "key generation failed" })),
            );
        }
    };

    // Also prepare the public part of the ephemeral key we have used for the
    // key derivation step above
    // WARNING: when encoding in base64, the decoder will run inside an SGX
    // enclave, and our home-baked base64 decoding assumes STANDARD (not
    // URL_SAFE) encoding
    let server_pub_key = my_private_key.compute_public_key().unwrap();
    let server_pub_key_le = sec1_pubkey_to_sgx(server_pub_key.as_ref()).unwrap();
    let server_pub_b64 = general_purpose::STANDARD.encode(server_pub_key_le);

    // Now do the key derivation
    let shared_secret: Vec<u8> =
        match agreement::agree_ephemeral(my_private_key, &peer_pubkey, |shared_secret_material| {
            Ok::<Vec<u8>, ring::error::Unspecified>(shared_secret_material.to_vec())
        }) {
            Ok(secret) => secret.unwrap(),
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "EC key agreement failed" })),
                );
            }
        };

    // WARNING: the SGX-SDK only implements AES 128, so we must use it here
    // instead of AES 256
    let cipher = match Aes128Gcm::new_from_slice(&shared_secret[..16]) {
        Ok(cipher) => cipher,
        Err(e) => {
            error!("error initializing AES 128 GCM cipher: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "JWT encoding failed" })),
            );
        }
    };

    let claims = match JwtClaims::new("sgx") {
        Ok(claims) => claims,
        Err(e) => {
            error!("error gathering JWT claims (error={e:?})");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "JWT claims gathering" })),
            );
        }
    };
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::RS256,
        ..Default::default()
    };
    let jwt = match jsonwebtoken::encode(&header, &claims, &state.jwt_encoding_key) {
        Ok(t) => t,
        Err(e) => {
            error!("JWT encode error (error={e:?})");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "JWT encoding failed" })),
            );
        }
    };

    // Encrypt the JWT
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = match cipher.encrypt(&nonce, jwt.as_bytes()) {
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

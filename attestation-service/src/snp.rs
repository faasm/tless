use crate::{
    ecdhe,
    jwt::{self, JwtClaims},
    mock::{MockQuote, MockQuoteType},
    request::{NodeData, Tee},
    state::AttestationServiceState,
};
use axum::{Extension, Json, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose};
use log::{debug, error, info};
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

/// # Description
///
/// This struct corresponds to the request that SNP-Knative sends to verify an
/// SNP attestation report.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnpRequest {
    /// Attributes used for CP-ABE keygen.
    node_data: NodeData,
    _init_time_data: InitTimeData,
    /// Base64-encoded SNP quote.
    quote: String,
    /// Additional base64-encoded data that we send with the enclave as part of
    /// the enclave held data. Even if slightly redundant, it is easier to
    /// access as a standalone field, and we check its integrity from the
    /// quote itself, which is signed by the QE.
    runtime_data: RuntimeData,
}

pub async fn verify_snp_report(
    Extension(state): Extension<Arc<AttestationServiceState>>,
    Json(payload): Json<SnpRequest>,
) -> impl IntoResponse {
    // Decode the quote
    let raw_quote_b64 = payload.quote.replace(['\n', '\r'], "");
    let quote_bytes = match general_purpose::URL_SAFE.decode(&raw_quote_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("invalid base64 string in SNP quote (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in quote" })),
            );
        }
    };

    let report_data_bytes: Vec<u8> = if state.mock_attestation {
        match MockQuote::from_bytes(&quote_bytes) {
            Ok(mock_quote) => {
                if mock_quote.quote_type != MockQuoteType::Snp {
                    error!("invalid mock SNP quote (error=wrong quote type)");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "invalid mock SNP quote" })),
                    );
                }
                info!("received mock SNP quote, skipping verification");
                mock_quote.user_data
            }
            Err(e) => {
                error!("invalid mock SNP quote (error={e:?})");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid mock SNP quote" })),
                );
            }
        }
    } else {
        // FIXME(#25): validate SNP reports on bare metal
        error!("missing logic to validate SNP reports on bare metal");
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({ "error": "SNP report validation not implemented" })),
        );
    };

    // Use the enclave held data (runtime_data) public key, to derive an
    // encryption key to protect the returned JWT, which contains secrets.
    debug!("decoding base64 encoded public key in quote.runtime_data");
    let raw_pubkey_bytes = match general_purpose::URL_SAFE.decode(&payload.runtime_data.data) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in runtimeData.data" })),
            );
        }
    };

    // Verify that the raw-bytes included in the runtime data match the enclave held
    // data in the verified report.
    if raw_pubkey_bytes != report_data_bytes {
        error!(
            "enclave held data does not match verified report data (expected={raw_pubkey_bytes:?}, got={:?})",
            report_data_bytes
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "enclave held data does not match verified report data" })),
        );
    }

    debug!("parsing pub key bytes to SEC1 format");
    let pubkey_bytes = match ecdhe::raw_pubkey_to_sec1_format(&raw_pubkey_bytes) {
        Some(b) => b,
        None => {
            error!("error converting SNP public key to SEC1 format");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid public key length" })),
            );
        }
    };
    if !ecdhe::is_valid_p256_point(&pubkey_bytes) {
        error!("error validating SNP-provided public key");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid EC public key" })),
        );
    }

    let (server_pub_key, shared_secret) =
        match ecdhe::generate_ecdhe_keys_and_derive_secret(&pubkey_bytes) {
            Ok(res) => res,
            Err(e) => {
                error!("error generating ECDH keys or deriving secret (error={e:?})");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "key generation or derivation failed" })),
                );
            }
        };

    let server_pub_key_le = ecdhe::sec1_pubkey_to_raw(&server_pub_key).unwrap();
    let server_pub_b64 = general_purpose::URL_SAFE.encode(server_pub_key_le);

    debug!("encoding JWT with server's private key (for authenticity)");
    let claims = match JwtClaims::new(
        &state,
        &Tee::Snp,
        &payload.node_data.gid,
        &payload.node_data.workflow_id,
        &payload.node_data.node_id,
    ) {
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

    match jwt::encrypt_jwt(jwt, shared_secret, server_pub_b64) {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(e) => {
            error!("error encrypting JWT (error={e:?})");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "JWT encryption failed" })),
            )
        }
    }
}

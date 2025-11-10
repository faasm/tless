use crate::{jwt::JwtClaims, request::NodeData, state::AttestationServiceState};
use axum::{Extension, Json, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose};
use log::error;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

/// # Description
///
/// This struct corresponds to the request that SNP-Knative sends to verify an
/// SNP attestation report.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnpRequest {
    /// Attributes used for CP-ABE keygen.
    node_data: NodeData,
    /// Base64-encoded SNP quote.
    quote: String,
}

pub async fn verify_snp_report(
    Extension(state): Extension<Arc<AttestationServiceState>>,
    Json(payload): Json<SnpRequest>,
) -> impl IntoResponse {
    // Convert raw body to Bytes
    let _quote_bytes = match general_purpose::URL_SAFE.decode(&payload.quote) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("invalid base64 string in SNP quote (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in quote" })),
            );
        }
    };

    #[cfg(feature = "azure-cvm")]
    match snpguest::verify::attestation::verify_attestation(&state.vcek_pem, bytes.as_ref()) {
        Ok(()) => {
            let claims = match JwtClaims::new("snp-acvm") {
                Ok(claims) => claims,
                Err(e) => {
                    error!("error gathering JWT claims (error={e:?})");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "JWT claims gathering" })),
                    );
                }
            };

            match jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claims,
                &state.jwt_encoding_key,
            ) {
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

    // FIXME(#25): validate SNP reports on bare metal
    error!("missing logic to validate SNP reports on bare metal");

    let claims = match JwtClaims::new(
        &state,
        "snp",
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
    match jsonwebtoken::encode(&header, &claims, &state.jwt_encoding_key) {
        Ok(token) => (StatusCode::OK, Json(json!({"token": token}))),
        Err(e) => {
            error!("error encoding JWT (error={e:?})");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to encode JWT" })),
            )
        }
    }

    // FIXME: finish the encryption of the JWT
}

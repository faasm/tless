use crate::{jwt::JwtClaims, state::AttestationServiceState};
use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    http::StatusCode,
    response::IntoResponse,
};
use log::error;
use serde_json::json;
use std::sync::Arc;

pub async fn verify_snp_report(
    Extension(state): Extension<Arc<AttestationServiceState>>,
    body: Body,
) -> impl IntoResponse {
    // Convert raw body to Bytes
    let full_body = to_bytes(body, 1024 * 1024).await;

    match full_body {
        Ok(_bytes) => {
            #[cfg(feature = "azure-cvm")]
            match snpguest::verify::attestation::verify_attestation(&state.vcek_pem, bytes.as_ref())
            {
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
            let claims = match JwtClaims::new("snp") {
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
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid body"})),
        ),
    }
}

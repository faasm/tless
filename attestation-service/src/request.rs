//! This module contains the common structures shared by diferent requests that
//! the attestation service receives.

use crate::state::AttestationServiceState;
use ark_serialize::CanonicalSerialize;
use axum::{Extension, extract::Json, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose};
use log::error;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fmt, sync::Arc};

/// # Description
///
/// This structure contains the data that callers must provide to run CP-ABE key
/// generation in the attestation service.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeData {
    /// Unique global user identififer.
    pub gid: String,
    /// Workflow identifier.
    pub workflow_id: String,
    /// Node identifier within the workflow.
    pub node_id: String,
}

pub enum Tee {
    #[allow(dead_code)]
    AzureCvm,
    Sgx,
    Snp,
}

impl fmt::Display for Tee {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Tee::AzureCvm => write!(f, "azure-cvm"),
            Tee::Sgx => write!(f, "sgx"),
            Tee::Snp => write!(f, "snp"),
        }
    }
}

#[derive(Serialize)]
pub struct StateResponse {
    pub id: String,
    pub mpk: String,
}

pub async fn get_state(
    Extension(state): Extension<Arc<AttestationServiceState>>,
) -> impl IntoResponse {
    let mut mpk_bytes = Vec::new();
    if let Err(e) = state.partial_mpk.serialize_compressed(&mut mpk_bytes) {
        error!("error serializing partial MPK (error={e:?})");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "error serializing partial MPK" })),
        );
    }

    let response = StateResponse {
        id: state.id.clone(),
        mpk: general_purpose::STANDARD.encode(&mpk_bytes),
    };

    let response_json = match serde_json::to_value(&response) {
        Ok(value) => value,
        Err(e) => {
            error!("error serializing response to JSON value (error={e:?})");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "error serializing response to JSON value" })),
            );
        }
    };

    (StatusCode::OK, Json(response_json))
}

use crate::{
    amd::{SnpCa, SnpProcType, SnpReport, SnpVcek, fetch_ca_from_kds, fetch_vcek_from_kds},
    ecdhe,
    jwt::{self, JwtClaims},
    mock::{MockQuote, MockQuoteType},
    request::{NodeData, Tee},
    state::AttestationServiceState,
};
use anyhow::Result;
use axum::{Extension, Json, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose};
use log::{debug, error, info};
use serde::Deserialize;
use serde_json::json;
use sev::{certs::snp::Verifiable, parser::ByteParser};
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

/// Extract the report payload from the PSP reposnse.
///
/// The attestation-service receives from SNP clients the literal response
/// returned by the PSP. The structure of this response is described in Table 25
/// [1]. We observe that the actual report is padded, so this method extracts
/// the actual attestation report from the PSP response. Note that crates like
/// snpguest manipulate the actual report, and not the PSP response. They would
/// rely on the `sev` crate to do the parsing but, annoyingly, it does not
/// expose a public API for us to parse the PSP response from bytes.
///
/// [1] https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf
///
/// # Arguments
///
/// - `psp_response`: the raw PSP response from the SNP_GET_REPORT command.
///
/// # Returns
///
/// The report byte array within the PSP response.
fn extract_report(data: &[u8]) -> Result<Vec<u8>> {
    const OFFSET_STATUS: usize = 0x00;
    const OFFSET_REPORT_SIZE: usize = 0x04;
    const OFFSET_REPORT_DATA: usize = 0x20;

    // We need at least 0x20 (32) bytes to reach the report data start.
    if data.len() < OFFSET_REPORT_DATA {
        let reason = format!(
            "PSP response buffer too short to contain header (got={}, minimum={OFFSET_REPORT_DATA})",
            data.len()
        );
        error!("{reason}");
        anyhow::bail!(reason);
    }

    // Check status.
    let status_bytes: [u8; 4] = data[OFFSET_STATUS..OFFSET_STATUS + 4].try_into()?;
    let status = u32::from_le_bytes(status_bytes);
    if status != 0 {
        let reason = format!("PSP reported firmware error (error={:#x})", status);
        error!("{}", reason);
        anyhow::bail!(reason);
    }

    // Get the report size.
    let size_bytes: [u8; 4] = data[OFFSET_REPORT_SIZE..OFFSET_REPORT_SIZE + 4].try_into()?;
    let report_size = u32::from_le_bytes(size_bytes) as usize;

    // Validate that the buffer actually holds the amount of data declared.
    let required_len = OFFSET_REPORT_DATA + report_size;
    if data.len() < required_len {
        let reason = "report is shorter than expected size";
        error!("{}", reason);
        anyhow::bail!(reason);
    }

    // Extract report. We slice from 0x20 to (0x20 + size) and convert to an owned
    // vec.
    let report_payload = data[OFFSET_REPORT_DATA..required_len].to_vec();
    Ok(report_payload)
}

async fn get_snp_ca(
    proc_type: &SnpProcType,
    state: &Arc<AttestationServiceState>,
) -> Result<SnpCa> {
    debug!("get_snp_ca(): getting CA chain for SNP processor (type={proc_type})");

    // Fast path: read CA from the cache.
    let ca: Option<SnpCa> = {
        let cache = state.amd_signing_keys.read().await;
        cache.get(proc_type).cloned()
    };

    if let Some(ca) = ca {
        debug!("get_snp_ca(): cache hit, fetching CA from local cache");
        return Ok(ca);
    }

    // This method also verifies the CA signatures.
    debug!("get_snp_ca(): cache miss, fetching CA from AMD's KDS");
    let ca = fetch_ca_from_kds(proc_type).await?;

    // Cache CA for future use.
    {
        let mut cache = state.amd_signing_keys.write().await;
        cache.insert(proc_type.clone(), ca.clone());
    }

    Ok(ca)
}

/// Helper method to fetch the VCEK certificate to validate an SNP quote. We
/// cache the certificates based on the platform and TCB info to avoid
/// round-trips to the AMD servers during verification (in the general case).
async fn get_snp_vcek(report: &SnpReport, state: &Arc<AttestationServiceState>) -> Result<SnpVcek> {
    // Fetch the certificate chain from the processor model.
    let proc_type = snpguest::fetch::get_processor_model(report)?;
    let ca = get_snp_ca(&proc_type, state).await?;

    // Work-out cache key from report.
    let tcb_version = report.reported_tcb;
    let cache_key = (proc_type.clone(), tcb_version);
    debug!(
        "get_snp_vcek(): fetching VCEK key for report (proc_type={proc_type}, tcb={tcb_version})"
    );

    // Fast path: read VCEK from the cache.
    let vcek: Option<SnpVcek> = {
        let cache = state.snp_vcek_cache.read().await;
        cache.get(&cache_key).cloned()
    };

    if let Some(vcek) = vcek {
        debug!("get_snp_vcek(): cache hit, fetching VCEK from local cache");
        return Ok(vcek);
    }

    // Slow path: fetch collateral from AMD's KDS.
    debug!("get_snp_vcek(): cache miss, fetching VCEK from AMD's KDS");
    let vcek = fetch_vcek_from_kds(&proc_type, report).await?;

    // Once we fetch a new VCEK, verify its certificate chain before caching it.
    (&ca.ask, &vcek).verify()?;

    // Cache VCEK for future use.
    {
        let mut cache = state.snp_vcek_cache.write().await;
        cache.insert(cache_key, vcek.clone());
    }

    Ok(vcek)
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
            error!("verify_snp_report(): invalid base64 string in SNP quote (error={e:?})");
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
                    error!("verify_snp_report(): invalid mock SNP quote (error=wrong quote type)");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "invalid mock SNP quote" })),
                    );
                }
                info!("verify_snp_report(): received mock SNP quote, skipping verification");
                mock_quote.user_data
            }
            Err(e) => {
                error!("verify_snp_report(): invalid mock SNP quote (error={e:?})");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid mock SNP quote" })),
                );
            }
        }
    } else {
        // Even though the response from the PSP to SNP_GET_REPORT is padded to 4000
        // bytes [1], the snpguest crate expects the AttestationReport to be the
        // exact size in bytes, without padding [2]. We receive from the client
        // the raw response from the PSP, so we must remove the padding first.
        // The structure of the PSP response can be found in Table 25 [3].
        //
        // [1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/sev-guest.h
        // [2] https://github.com/virtee/sev/blob/c7b6bbb4e9c0fe85199723ab082ccadf39a494f0/src/firmware/linux/guest/types.rs#L169-L183
        // [3] https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf
        let report_body = match extract_report(&quote_bytes) {
            Ok(report_body) => report_body,
            Err(e) => {
                error!("verify_snp_report(): error extracting report body (error={e:?})");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid SNP quote" })),
                );
            }
        };

        // Parse the attestation report from bytes.
        let report: SnpReport = match SnpReport::from_bytes(&report_body) {
            Ok(report) => report,
            Err(e) => {
                error!("verify_snp_report(): error parsing bytes to SNP report (error={e:?})");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "error parsing SNP report" })),
                );
            }
        };

        // Fetch the VCEK certificate.
        let vcek = match get_snp_vcek(&report, &state).await {
            Ok(report) => report,
            Err(e) => {
                error!("verify_snp_report(): error fetching SNP VCEK (error={e:?})");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "error fetching SNP VCEK" })),
                );
            }
        };

        // FIXME(#55): also check the SNP measurement against a reference value.
        match snpguest::verify::attestation::verify_attestation(&vcek, &report) {
            Ok(()) => {
                info!("verify_snp_report(): verified SNP report");

                // Report data to owned vec.
                report.report_data.to_vec()
            }
            Err(e) => {
                error!("error verifying SNP report (error={e:?})");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "error verifying SNP report" })),
                );
            }
        }
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

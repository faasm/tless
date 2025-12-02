use crate::{
    amd::get_snp_vcek,
    ecdhe,
    request::{Tee, snp::SnpRequest},
    state::AttestationServiceState,
};
use anyhow::Result;
use axum::{Extension, Json, http::StatusCode, response::IntoResponse};
use az_snp_vtpm::{
    hcl::HclReport,
    report::{AttestationReport, Validateable},
    vtpm::Quote,
};
use base64::{Engine as _, engine::general_purpose};
use log::{error, info};
use openssl::{pkey::PKey, x509::X509};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// Structure to work-around the lack of a Quote::new constructor in the
/// az-snp-vtpm crate.
#[derive(Serialize, Deserialize)]
struct QuoteRepr {
    signature: Vec<u8>,
    message: Vec<u8>,
    pcrs: Vec<[u8; 32]>,
}

/// Build a `Quote` from its parts without modifying az_vtpm_snp.
///
/// This relies on both `Quote` and `QuoteRepr` having the same
/// serde representation (same field names & types).
pub fn quote_from_parts(
    signature: Vec<u8>,
    message: Vec<u8>,
    pcrs: Vec<[u8; 32]>,
) -> Result<Quote> {
    let repr = QuoteRepr {
        signature,
        message,
        pcrs,
    };

    // Any serde format will do; JSON is simple and explicit.
    let json = serde_json::to_vec(&repr)?;
    let quote: Quote = serde_json::from_slice(&json)?;
    Ok(quote)
}

fn read_u32_le(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < 4 {
        anyhow::bail!("read_u32_le(): too short");
    }
    let b: [u8; 4] = bytes[0..4].try_into()?;
    Ok(u32::from_le_bytes(b))
}

/// Parse the vTPM report and the vTPM quote from the raw bytes received from
/// the client.
///
/// We follow a wire-format specified in `./accless/libs/attestation/snp.cpp`
/// which combines in a single byte array the vTPM report, the vTPM quote's
/// message and the vTPM quote's signature.
///
/// The wire-format layout is as follows:
/// [0..3]   = reportLen (LE)
/// [4..7]   = msgLen    (LE)
/// [8..11]  = sigLen    (LE)
/// [12..]   = report || msg || sig
fn parse_quote_bytes(quote_bytes: &[u8]) -> Result<(HclReport, Quote)> {
    if quote_bytes.len() < 12 {
        let reason = format!(
            "quote bytes too short (expected >= 12, got={})",
            quote_bytes.len()
        );
        error!("parse_quote_bytes(): {reason}");
        anyhow::bail!(reason);
    }

    let report_len = read_u32_le(&quote_bytes[0..4])? as usize;
    let msg_len = read_u32_le(&quote_bytes[4..8])? as usize;
    let sig_len = read_u32_le(&quote_bytes[8..12])? as usize;

    let expected = 12usize
        .checked_add(report_len)
        .and_then(|v| v.checked_add(msg_len))
        .and_then(|v| v.checked_add(sig_len))
        .ok_or(anyhow::anyhow!("parse_quote_bytes(): invalid length"))?;

    if quote_bytes.len() < expected {
        let reason = format!(
            "quote length mismatch (expected={expected}, got={})",
            quote_bytes.len()
        );
        error!("parse_quote_bytes(): {reason}");
        anyhow::bail!(reason);
    }

    let mut offset = 12usize;
    let report_end = offset + report_len;
    let vtpm_report = HclReport::new(quote_bytes[offset..report_end].to_vec())?;
    offset = report_end;

    let msg_end = offset + msg_len;
    let quote_message = quote_bytes[offset..msg_end].to_vec();
    offset = msg_end;

    let sig_end = offset + sig_len;
    let quote_signature = quote_bytes[offset..sig_end].to_vec();

    // FIXME: currently we don't include the PCR values in the parsed quote, so we
    // cannot use them during verification to compare them against golden
    // values.
    let quote = quote_from_parts(quote_signature, quote_message, Vec::<[u8; 32]>::new())?;

    Ok((vtpm_report, quote))
}

pub async fn verify_snp_vtpm_report(
    Extension(state): Extension<Arc<AttestationServiceState>>,
    Json(payload): Json<SnpRequest>,
) -> impl IntoResponse {
    // Decode the quote.
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

    let (vtpm_report, vtpm_quote) = match parse_quote_bytes(&quote_bytes) {
        Ok((report, quote)) => (report, quote),
        Err(e) => {
            error!("verify_snp_vtpm_report(): error parsing quote bytes (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid quote bytes" })),
            );
        }
    };

    // The vTPM report is a static SNP report, signed by the host's VCEK, that is
    // loaded on boot in the vTPM. As runtime_data, it contains the vTPM's
    // Attestation Key (AK).
    let ak_pub = match vtpm_report.ak_pub() {
        Ok(ak_pub) => ak_pub,
        Err(e) => {
            error!("verify_snp_vtpm_report(): error extracting AK from vTPM report (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid vTPM report" })),
            );
        }
    };
    let ak_pub_hash = vtpm_report.var_data_sha256();
    let snp_report: AttestationReport = match vtpm_report.try_into() {
        Ok(snp_report) => snp_report,
        Err(e) => {
            error!(
                "verify_snp_vtpm_report(): error parsing vTPM report into SNP report (error={e:?})"
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid vTPM report" })),
            );
        }
    };

    // Verify the SNP report using the host's VCEK.
    let vcek = match get_snp_vcek(&snp_report, &state).await {
        Ok(report) => report,
        Err(e) => {
            error!("verify_snp_report(): error fetching SNP VCEK (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "error fetching SNP VCEK" })),
            );
        }
    };
    // FIXME(#66): given the duplication between the `sev` and `az-snp-vtpm` crate,
    // we need to work-around their different Vcek definitions by converting to
    // an OpenSSL struct.
    let az_vcek = az_snp_vtpm::certs::Vcek(X509::from(vcek));
    match snp_report.validate(&az_vcek) {
        Ok(()) => {
            info!("verify_snp_vtpm_report(): verified SNP-vTPM report");
        }
        Err(e) => {
            error!("verify_snp_vtpm_report(): error verifying SNP report (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "error verifying SNP-vTPM report" })),
            );
        }
    }

    // Verify that the vTPM report contains the AK as runtime data.
    if ak_pub_hash != snp_report.report_data[..32] {
        error!("verify_snp_vtpm_report(): AK hash does not match report's runtime data");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "error verifying SNP-vTPM report" })),
        );
    }

    // Verify that the AK was signed the vTPM quote.
    let der = match ak_pub.key.try_to_der() {
        Ok(der) => der,
        Err(e) => {
            error!("verify_snp_vtpm_report(): error converting AK to DER (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "error converting AK to DER" })),
            );
        }
    };
    let pub_key = match PKey::public_key_from_der(&der) {
        Ok(pub_key) => pub_key,
        Err(e) => {
            error!("verify_snp_vtpm_report(): error converting DER to PKey (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "error converting DER to PKey" })),
            );
        }
    };
    let raw_pubkey_bytes = match general_purpose::URL_SAFE.decode(&payload.runtime_data.data) {
        Ok(b) => b,
        Err(e) => {
            error!("verify_snp_vtpm_report(): error decoding runtime_data (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid base64 in runtimeData.data" })),
            );
        }
    };
    match vtpm_quote.verify_signature(&pub_key) {
        Ok(()) => {
            info!("verify_snp_vtpm_report(): verified SNP-vTPM quote");
        }
        Err(e) => {
            error!("verify_snp_vtpm_report(): error verifying SNP quote (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "error verifying SNP-vTPM quote" })),
            );
        }
    };

    // Check that the nonce in the vTPM quote matches the public key in the request.
    let vtpm_nonce = match vtpm_quote.nonce() {
        Ok(vtpm_nonce) => vtpm_nonce,
        Err(e) => {
            error!("verify_snp_vtpm_report(): error extracting nonce from quote (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "error extracting nonce from quote" })),
            );
        }
    };
    if raw_pubkey_bytes != vtpm_nonce {
        error!("verify_snp_vtpm_report(): vTPM nonce and raw pubkey mismatch");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "vTPM nonce and raw pubkey mismatch" })),
        );
    }

    // FIXME(#55): now we would need to check that the different PCR values in the
    // PCR quote match some well-known values.

    // Now that we have verified the attestation report, run the server-side part of
    // the attribute minting protocol which involves running ECDHE and running
    // CP-ABE keygen.
    match ecdhe::do_ecdhe_ke(
        &state,
        &Tee::AzureCvm,
        &payload.node_data,
        &raw_pubkey_bytes,
    ) {
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

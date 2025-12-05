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
use sha2::Digest;
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

/// Extract the raw signature from the TPMT signature struct received from the
/// client.
///
/// The TPMT_SIGNATURE is described in (TPM 2.0 Library Spec, Part 2:
/// Structures) [1]. The marshalled form of the RSA signature is:
/// - sigAlg (u16) = TPM2_ALG_RSASSA | TPM2_ALG_RSAPSS
/// - hashAlg (u16) = hash selector (e.g. TPM2_ALG_SHA256)
/// - sig_len (u16)
/// - sig_bytes (sig_len)
///
/// We only need the signature bytes to perform the verification, so we discard
/// everything else. [1] https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-2-Structures.pdf
fn parse_tpmt_signature(sig: &[u8]) -> Result<Vec<u8>> {
    // These values are extracted from Table 9 in [1].
    const TPM2_ALG_RSASSA: u16 = 0x0014;
    const TPM2_ALG_RSAPSS: u16 = 0x0016;
    const TPM2_ALG_SHA256: u16 = 0x000b;

    if sig.len() < 6 {
        let reason = "TPMT_SIGNATURE too short";
        error!("parse_tpmt_signature(): {reason}");
        anyhow::bail!(reason);
    }

    let alg = u16::from_be_bytes([sig[0], sig[1]]);
    match alg {
        TPM2_ALG_RSASSA | TPM2_ALG_RSAPSS => {}
        other => {
            let reason = format!("unsupported TPM signature algorithm: {other:#06x}");
            error!("parse_tpmt_signature(): {reason}");
            anyhow::bail!(reason)
        }
    }
    let hash_alg = u16::from_be_bytes([sig[2], sig[3]]);
    if hash_alg != TPM2_ALG_SHA256 {
        let reason = format!("unsupported TPM hashing algroitghm: {hash_alg:#06x}");
        error!("parse_tpmt_signature(): {reason}");
        anyhow::bail!(reason)
    }

    let sig_len = u16::from_be_bytes([sig[4], sig[5]]) as usize;
    let start = 6;
    let end = start + sig_len;
    if sig.len() < end {
        let reason = "TPMT_SIGNATURE length exceeds payload";
        error!("parse_tpmt_signature(): {reason}");
        anyhow::bail!(reason);
    }

    Ok(sig[start..end].to_vec())
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
    let mut quote_message = quote_bytes[offset..msg_end].to_vec();
    offset = msg_end;

    // TPM returns TPM2B_ATTEST (len + TPMS_ATTEST), but the verifier expects just
    // TPMS_ATTEST.
    if quote_message.len() < 2 {
        anyhow::bail!("vTPM quote too short for TPM2B_ATTEST header");
    }
    let att_size = u16::from_be_bytes([quote_message[0], quote_message[1]]) as usize;
    if att_size + 2 > quote_message.len() {
        anyhow::bail!("vTPM quote length header exceeds payload");
    }
    quote_message = quote_message[2..2 + att_size].to_vec();

    let sig_end = offset + sig_len;
    let sig_raw = parse_tpmt_signature(&quote_bytes[offset..sig_end])?;

    // FIXME(#55): currently we don't include the PCR values in the parsed quote, so
    // we cannot use them during verification to compare them against golden
    // values.
    let quote = quote_from_parts(sig_raw, quote_message, Vec::<[u8; 32]>::new())?;

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
    // FIXME(#62): given the duplication between the `sev` and `az-snp-vtpm` crate,
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
    let ak_der = match ak_pub.key.try_to_der() {
        Ok(der) => der,
        Err(e) => {
            error!("verify_snp_vtpm_report(): error converting AK to DER (error={e:?})");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "error converting AK to DER" })),
            );
        }
    };
    let ak_pub_key = match PKey::public_key_from_der(&ak_der) {
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
    match vtpm_quote.verify_signature(&ak_pub_key) {
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
    // Given that the vTPM quote can only carry 32 bytes of data, we need to
    // first hash the raw public key bytes that we receive with the request.
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
    let raw_pubkey_hash = sha2::Sha256::digest(&raw_pubkey_bytes).to_vec();
    if raw_pubkey_hash != vtpm_nonce {
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

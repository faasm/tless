use crate::{
    jwt::{self, JwtClaims},
    request::{NodeData, Tee},
    state::AttestationServiceState,
};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use log::{debug, error};
use p256::PublicKey;
use ring::{
    agreement::{self, ECDH_P256, UnparsedPublicKey},
    rand::SystemRandom,
};

/// Checks if a given byte array represents a valid P-256 elliptic curve point.
///
/// # Arguments
///
/// - `bytes`: A slice of bytes representing the public key.
///
/// # Returns
///
/// `true` if the bytes represent a valid P-256 point, `false` otherwise.
fn is_valid_p256_point(bytes: &[u8]) -> bool {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return false;
    }
    PublicKey::from_sec1_bytes(bytes).is_ok()
}

/// Converts a public key format (concatenated little-endian X and Y
/// coordinates) to SEC1 (Standard for Efficient Cryptography) format (0x04 || X
/// || Y).
///
/// The SGX and SNP clients manually serialize the public key, but the
/// attestation service needs it in SEC1 format for rust crypto.
///
/// # Arguments
///
/// - `raw`: A slice of 64 bytes representing the SGX public key.
///
/// # Returns
///
/// An `Option` containing a 65-byte array in SEC1 format if successful, `None`
/// otherwise.
fn raw_pubkey_to_sec1_format(raw: &[u8]) -> Option<[u8; 65]> {
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

/// Converts a SEC1 formatted public key (0x04 || X || Y) to the raw public key
/// format (concatenated little-endian X and Y coordinates).
///
/// # Arguments
///
/// - `sec1_pubkey`: A slice of bytes representing the SEC1 formatted public
///   key.
///
/// # Returns
///
/// A `Result` containing a `Vec<u8>` in raw format if successful, or an
/// `anyhow::Error` otherwise.
fn sec1_pubkey_to_raw(sec1_pubkey: &[u8]) -> Result<Vec<u8>> {
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

/// Generates an ephemeral ECDH key pair and derives a shared secret using the
/// provided peer's public key.
///
/// # Arguments
///
/// - `peer_pubkey_bytes`: A slice of bytes representing the peer's public key
///   in SEC1 format.
///
/// # Returns
///
/// A `Result` containing a tuple of `(server_public_key, shared_secret)` as
/// `Vec<u8>` if successful, or an `anyhow::Error` otherwise.
pub fn generate_ecdhe_keys_and_derive_secret(
    peer_pubkey_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let peer_pubkey = UnparsedPublicKey::new(&ECDH_P256, peer_pubkey_bytes);

    let rng = SystemRandom::new();
    let my_private_key = agreement::EphemeralPrivateKey::generate(&ECDH_P256, &rng)?;

    let my_pubkey = my_private_key.compute_public_key()?;

    let shared_secret =
        agreement::agree_ephemeral(my_private_key, &peer_pubkey, |shared_secret_material| {
            Ok::<Vec<u8>, ring::error::Unspecified>(shared_secret_material.to_vec())
        })??;

    Ok((my_pubkey.as_ref().to_vec(), shared_secret))
}

pub async fn do_ecdhe_ke(
    state: &AttestationServiceState,
    tee: &Tee,
    node_data: &NodeData,
    raw_pubkey_bytes: &[u8],
) -> Result<serde_json::Value> {
    debug!("parsing pub key bytes to SEC1 format");
    let pubkey_bytes = raw_pubkey_to_sec1_format(raw_pubkey_bytes)
        .context("do_ecdhe_ke(): error parsing pubkey to SEC1")?;
    if !is_valid_p256_point(&pubkey_bytes) {
        let reason = "error validating SGX-provided public key";
        error!("do_ecdhe_ke(): {reason}");
        anyhow::bail!(reason);
    }

    let (server_pub_key, shared_secret) = generate_ecdhe_keys_and_derive_secret(&pubkey_bytes)
        .context("do_ecdhe_ke(): error deriving shared secret")?;
    let server_pub_key_le = sec1_pubkey_to_raw(&server_pub_key).unwrap();
    let server_pub_b64 = general_purpose::URL_SAFE.encode(server_pub_key_le);

    debug!("encoding JWT with server's private key (for authenticity)");
    let claims = JwtClaims::new(
        state,
        tee,
        &node_data.gid,
        &node_data.workflow_id,
        &node_data.node_id,
    )
    .await
    .context("do_ecdhe_ke(): error generating JWT claims")?;
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::RS256,
        ..Default::default()
    };
    let jwt = jsonwebtoken::encode(&header, &claims, &state.jwt_encoding_key)
        .context("do_ecdhe_ke(): error encoding JSON web token")?;

    // Encrypt JWT with derived shared secret.
    jwt::encrypt_jwt(jwt, shared_secret, server_pub_b64)
}

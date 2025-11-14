use anyhow::Result;
use p256::PublicKey;
use ring::{
    agreement::{self, ECDH_P256, UnparsedPublicKey},
    rand::SystemRandom,
};

/// # Description
///
/// Checks if a given byte array represents a valid P-256 elliptic curve point.
///
/// # Arguments
///
/// - `bytes`: A slice of bytes representing the public key.
///
/// # Returns
///
/// `true` if the bytes represent a valid P-256 point, `false` otherwise.
pub fn is_valid_p256_point(bytes: &[u8]) -> bool {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return false;
    }
    PublicKey::from_sec1_bytes(bytes).is_ok()
}

/// # Description
///
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
pub fn raw_pubkey_to_sec1_format(raw: &[u8]) -> Option<[u8; 65]> {
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

/// # Description
///
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
pub fn sec1_pubkey_to_raw(sec1_pubkey: &[u8]) -> Result<Vec<u8>> {
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

/// # Description
///
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

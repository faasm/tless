//! This module implements the hybrid CP-ABE scheme that derives a CP-ABE scheme
//! from a CP-ABE Key Encapsulation Mechanism and a symmetric encryption
//! function. We use AES-GCM-128 as that is all the randomness we can get out
//! of our CP-ABEKEM scheme.

use crate::{Ciphertext, Gt, Iota, MPK, Policy, Tau, USK, decrypt, encrypt};
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{CryptoRng, RngCore};
use hkdf::Hkdf;
use log::error;
use sha2::Sha256;
use zeroize::Zeroize;

const ABE4_KDF_SALT: &[u8] = b"accless-abe4-kem-salt";
const ABE4_KDF_INFO: &[u8] = b"accless-abe4-aes-gcm-128";

#[derive(Clone)]
pub struct HybridCiphertext {
    /// CP-ABE ciphertext.
    pub abe_ct: Ciphertext,
    /// Symmetric ciphertext CTsym = nonce || AES-GCM ciphertext+tag.
    pub sym_ct: Vec<u8>,
}

impl HybridCiphertext {
    pub fn new(abe_ct: Ciphertext, sym_ct: Vec<u8>) -> Self {
        Self { abe_ct, sym_ct }
    }
}

/// Derive an AES128 key from an element in Gt.
///
/// gt is, precisely, what we get after a successful call to encrypt of a
/// CP-ABEKEM scheme (i.e. the scheme we implement in the `scheme` module).
fn derive_aes128_key_from_gt(gt: &Gt) -> Result<[u8; 16]> {
    let mut gt_bytes = Vec::new();
    // This should never fail for a valid group element
    gt.serialize_compressed(&mut gt_bytes)
        .map_err(|e| anyhow::anyhow!("Gt serialization failed: {}", e))?;

    let hk = Hkdf::<Sha256>::new(Some(ABE4_KDF_SALT), &gt_bytes);

    let mut key = [0u8; 16];
    hk.expand(ABE4_KDF_INFO, &mut key)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;

    // gt_bytes only holds public data, no need to zeroize, but we could:
    gt_bytes.zeroize();

    Ok(key)
}

/// Encrypt `plaintext` using AES-GCM-128 under a key derived from `gt`.
///
/// # Returns
///
/// A symmetrically encrypted CT as : nonce (12 bytes) || ciphertext + tag.
fn sym_encrypt_gt<R: RngCore + CryptoRng>(
    rng: &mut R,
    gt: &Gt,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let mut key_bytes = derive_aes128_key_from_gt(gt)?;
    let cipher = Aes128Gcm::new_from_slice(&key_bytes)?;

    // 96-bit nonce as recommended for GCM.
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let mut ct = cipher.encrypt(&nonce, payload).map_err(|e| {
        let reason = format!("error running AES-128-GCM encryption (error={e:?})");
        error!("sym_encrypt_gt(): {reason}");
        anyhow::anyhow!(reason)
    })?;

    // CTsym = nonce || ct.
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.append(&mut ct);

    // Zeroize key material.
    key_bytes.zeroize();

    Ok(out)
}

/// Decrypt `sym_ct` using AES-GCM-128 with key derived from `gt`.
/// Expects sym_ct = nonce (12 bytes) || ciphertext + tag.
fn sym_decrypt_gt(gt: &Gt, sym_ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sym_ct.len() < 12 {
        let reason = "ciphertext too short";
        error!("sym_decrypt_gt(): {reason}");
        anyhow::bail!(reason);
    }

    let (nonce_bytes, ct_bytes) = sym_ct.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes.try_into().map_err(|e| {
        let reason = format!("ciphertext too short for nonce (error={e:?})");
        error!("sym_decrypt_gt(): {reason}");
        anyhow::anyhow!(reason)
    })?;
    let nonce = Nonce::from(nonce_arr);

    let mut key_bytes = derive_aes128_key_from_gt(gt)?;
    let cipher = Aes128Gcm::new_from_slice(&key_bytes)?;

    let payload = Payload { msg: ct_bytes, aad };

    let pt = cipher.decrypt(&nonce, payload).map_err(|e| {
        let reason = format!("error running AES-128-GCM decryption (error={e:?})");
        error!("sym_decrypt_gt(): {reason}");
        anyhow::anyhow!(reason)
    })?;

    key_bytes.zeroize();

    Ok(pt)
}

/// Hybrid CP-ABE + AES-GCM encryption.
///
/// This is the ABE.Encrypt from Appendix A.3, instantiated with:
/// - The CP-ABE encryption method in `scheme` -> opt4 from Abe-Cubed.
/// - A symmetric encryption scheme -> AES-GCM-128
/// - KDF -> Rely on the HKDF crate.
pub fn encrypt_hybrid<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &MPK,
    policy: &Policy,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<HybridCiphertext> {
    let tau = Tau::new(policy);

    // Encapsulate: (CTA, K) where K = Gt
    let (gt, abe_ct) = encrypt(&mut *rng, mpk, policy, &tau);

    // Symmetric encryption under KDF(K)
    let sym_ct = sym_encrypt_gt(rng, &gt, plaintext, aad)?;

    Ok(HybridCiphertext::new(abe_ct, sym_ct))
}

/// Hybrid CP-ABE + AES-GCM decryption.
///
/// This is the ABE.Decrypt from Appendix A.3:
///  - K <- KEM.Decaps(...)
///  - M <- SE.SymDecrypt_{KDF(K)}(CTsym)
pub fn decrypt_hybrid(
    usk: &USK,
    gid: &str,
    policy: &Policy,
    abe_ct: &Ciphertext,
    sym_ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let tau = Tau::new(policy);
    let user_attrs = usk.get_user_attributes();
    let iota = Iota::new(&user_attrs);

    // KEM decapsulation step.
    let gt_opt = decrypt(usk, gid, &iota, &tau, policy, abe_ct);
    let gt = match gt_opt {
        Some(g) => g,
        None => {
            let reason = "CP-ABE decryption failed";
            error!("decrypt_hybrid(): {reason}");
            anyhow::bail!(reason);
        }
    };

    // Symmetric decryption under KDF(K)
    sym_decrypt_gt(&gt, sym_ct, aad)
}

mod curve;
mod hashing;
pub mod hybrid;
pub mod policy;
pub mod scheme;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::engine::{Engine as _, general_purpose};
pub use curve::Gt;
pub use hybrid::{decrypt_hybrid, encrypt_hybrid};
pub use policy::{Policy, UserAttribute};
pub use scheme::{decrypt, encrypt, iota, keygen, setup, tau};
use scheme::{
    iota::Iota,
    tau::Tau,
    types::{Ciphertext, MPK, MSK, USK},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    os::raw::c_char,
};

// -------------------------------------------------------------------------------------------------
// FFI
// -------------------------------------------------------------------------------------------------

/// Free a C string returned from this library
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn policy_authorities_abe4(policy_str: *const c_char) -> *mut c_char {
    let policy_cstr = unsafe { CStr::from_ptr(policy_str) };
    let policy_str = match policy_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert policy C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let policy = match Policy::parse(policy_str) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to parse policy: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    let mut authorities = BTreeSet::new();
    for idx in 0..policy.len() {
        authorities.insert(policy.get(idx).0.authority().to_string());
    }

    let authorities: Vec<String> = authorities.into_iter().collect();
    let json = match serde_json::to_string(&authorities) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to serialize policy authorities to JSON: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    match CString::new(json) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to create CString for policy authorities: {}",
                e
            );
            std::ptr::null_mut()
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SetupOutput {
    msk: String,
    mpk: String,
}

/// # Description
///
/// FFI wrapper for the CP-ABE setup function for a single authority.
///
/// This function takes a C-style string representing the unique identifier of
/// the authority. It generates a Master Secret Key (MSK) and a Master Public
/// Key (MPK) for this authority.
///
/// # Arguments
///
/// * `auth_id_cstr`: A C-style string containing the unique identifier of the
///   authority.
///
/// # Returns
///
/// A C-style string containing a JSON object with two fields:
/// - `msk`: The base64-encoded Master Secret Key for the authority.
/// - `mpk`: The base64-encoded Master Public Key for the authority.
///
/// Returns a null pointer on error.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setup_partial_abe4(auth_id_cstr: *const c_char) -> *mut c_char {
    let auth_id_str = match unsafe { CStr::from_ptr(auth_id_cstr).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert authority ID C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let mut rng = ark_std::rand::thread_rng();
    let (partial_msk, partial_mpk) = scheme::setup_partial(&mut rng, auth_id_str);

    let mut msk_bytes = Vec::new();
    if partial_msk.serialize_compressed(&mut msk_bytes).is_err() {
        eprintln!("[accless-abe4-rs] Failed to serialize PartialMSK");
        return std::ptr::null_mut();
    }

    let mut mpk_bytes = Vec::new();
    if partial_mpk.serialize_compressed(&mut mpk_bytes).is_err() {
        eprintln!("[accless-abe4-rs] Failed to serialize PartialMPK");
        return std::ptr::null_mut();
    }

    let output = SetupOutput {
        msk: general_purpose::STANDARD.encode(&msk_bytes),
        mpk: general_purpose::STANDARD.encode(&mpk_bytes),
    };

    let output_json = match serde_json::to_string(&output) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to serialize output to JSON: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    match CString::new(output_json) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to create CString: {}", e);
            std::ptr::null_mut()
        }
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setup_abe4(auths_json: *const c_char) -> *mut c_char {
    let auths_cstr = unsafe { CStr::from_ptr(auths_json) };

    let auths_str = match auths_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert auths C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let auths: Vec<String> = match serde_json::from_str(auths_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to parse auths JSON: {}", e);
            return std::ptr::null_mut();
        }
    };

    let auths_ref: Vec<&str> = auths.iter().map(|s| s.as_str()).collect();
    let mut rng = ark_std::rand::thread_rng();

    let (msk, mpk) = setup(&mut rng, &auths_ref);

    let mut msk_bytes = Vec::new();
    if msk.serialize_compressed(&mut msk_bytes).is_err() {
        eprintln!("[accless-abe4-rs] Failed to serialize MSK");
        return std::ptr::null_mut();
    }

    let mut mpk_bytes = Vec::new();
    if mpk.serialize_compressed(&mut mpk_bytes).is_err() {
        eprintln!("[accless-abe4-rs] Failed to serialize MPK");
        return std::ptr::null_mut();
    }

    let output = SetupOutput {
        msk: general_purpose::STANDARD.encode(&msk_bytes),
        mpk: general_purpose::STANDARD.encode(&mpk_bytes),
    };

    let output_json = match serde_json::to_string(&output) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to serialize output to JSON: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    match CString::new(output_json) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to create CString: {}", e);
            std::ptr::null_mut()
        }
    }
}

/// # Description
///
/// FFI wrapper for the CP-ABE key generation function for a single authority.
///
/// This function takes a C-style string representing the global identifier
/// (GID) of the user, a base64-encoded partial Master Secret Key (MSK), and
/// a JSON string representing the user's attributes. It generates a partial
/// User Secret Key (USK) for the given user and attributes.
///
/// # Arguments
///
/// * `gid_cstr`: A C-style string containing the global identifier of the user.
/// * `partial_msk_b64_cstr`: A C-style string containing the base64-encoded
///   partial Master Secret Key.
/// * `user_attrs_json`: A C-style string containing a JSON array of user
///   attributes.
///
/// # Returns
///
/// A C-style string containing the base64-encoded partial User Secret Key.
///
/// Returns a null pointer on error.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keygen_partial_abe4(
    gid_cstr: *const c_char,
    partial_msk_b64_cstr: *const c_char,
    user_attrs_json: *const c_char,
) -> *mut c_char {
    let gid_str = match unsafe { CStr::from_ptr(gid_cstr).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert GID C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let partial_msk_b64_str = match unsafe { CStr::from_ptr(partial_msk_b64_cstr).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert partial MSK C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let partial_msk_bytes = match general_purpose::STANDARD.decode(partial_msk_b64_str) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to decode partial MSK from base64: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let partial_msk: scheme::types::PartialMSK =
        match scheme::types::PartialMSK::deserialize_compressed(&partial_msk_bytes[..]) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[accless-abe4-rs] Failed to deserialize PartialMSK: {}", e);
                return std::ptr::null_mut();
            }
        };

    let user_attrs_str = match unsafe { CStr::from_ptr(user_attrs_json).to_str() } {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert user attributes C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let user_attrs: Vec<UserAttribute> = match serde_json::from_str(user_attrs_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to parse user attributes JSON: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let iota = Iota::new(&user_attrs);
    let mut rng = ark_std::rand::thread_rng();

    let user_attrs_refs: Vec<&UserAttribute> = user_attrs.iter().collect();
    let partial_usk =
        scheme::keygen_partial(&mut rng, gid_str, &partial_msk, &user_attrs_refs, &iota);

    let mut partial_usk_bytes = Vec::new();
    if partial_usk
        .serialize_compressed(&mut partial_usk_bytes)
        .is_err()
    {
        eprintln!("[accless-abe4-rs] Failed to serialize PartialUSK");
        return std::ptr::null_mut();
    }

    let partial_usk_b64 = general_purpose::STANDARD.encode(&partial_usk_bytes);
    match CString::new(partial_usk_b64) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to create CString for PartialUSK: {}",
                e
            );
            std::ptr::null_mut()
        }
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keygen_abe4(
    gid: *const c_char,
    msk_b64: *const c_char,
    user_attrs_json: *const c_char,
) -> *mut c_char {
    let gid_cstr = unsafe { CStr::from_ptr(gid) };
    let msk_b64_cstr = unsafe { CStr::from_ptr(msk_b64) };
    let user_attrs_cstr = unsafe { CStr::from_ptr(user_attrs_json) };

    let msk_b64_str = match msk_b64_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert MSK C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let msk_bytes = match general_purpose::STANDARD.decode(msk_b64_str) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to decode MSK from base64: {}", e);
            return std::ptr::null_mut();
        }
    };

    let msk: MSK = match MSK::deserialize_compressed(&msk_bytes[..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to deserialize MSK: {}", e);
            return std::ptr::null_mut();
        }
    };

    let user_attrs_str = match user_attrs_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert user attributes C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let user_attrs: Vec<UserAttribute> = match serde_json::from_str(user_attrs_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to parse user attributes JSON: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let iota = Iota::new(&user_attrs);
    let mut rng = ark_std::rand::thread_rng();

    let gid_str = match gid_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert GID C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let usk = keygen(&mut rng, gid_str, &msk, &user_attrs, &iota);

    let mut usk_bytes = Vec::new();
    if usk.serialize_compressed(&mut usk_bytes).is_err() {
        eprintln!("[accless-abe4-rs] Failed to serialize USK");
        return std::ptr::null_mut();
    }

    let usk_b64 = general_purpose::STANDARD.encode(&usk_bytes);
    match CString::new(usk_b64) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to create CString for USK: {}", e);
            std::ptr::null_mut()
        }
    }
}

#[derive(Serialize, Deserialize)]
struct EncryptOutput {
    gt: String,
    ciphertext: String,
}

/// # Description
///
/// FFI wrapper for the CP-ABE encryption function.
///
/// This function takes a base64-encoded master public key and a policy string,
/// encrypts a symmetric key under this policy, and returns the base64-encoded
/// encrypted symmetric key and its ciphertext.
///
/// # Arguments
///
/// * `mpk_b64`: A C-style string containing the base64-encoded master public
///   key.
/// * `policy_str`: A C-style string containing the policy string.
///
/// # Returns
///
/// A C-style string containing a JSON object with two fields:
/// - `gt`: The base64-encoded symmetric key (plaintext) that was encrypted.
/// - `ciphertext`: The base64-encoded ciphertext of the symmetric key.
///
/// Returns a null pointer on error.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn encrypt_abe4(
    mpk_b64: *const c_char,
    policy_str: *const c_char,
) -> *mut c_char {
    let mpk_b64_cstr = unsafe { CStr::from_ptr(mpk_b64) };
    let policy_cstr = unsafe { CStr::from_ptr(policy_str) };

    let mpk_b64_str = match mpk_b64_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert MPK C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let mpk_bytes = match general_purpose::STANDARD.decode(mpk_b64_str) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to decode MPK from base64: {}", e);
            return std::ptr::null_mut();
        }
    };

    let mpk: MPK = match MPK::deserialize_compressed(&mpk_bytes[..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to deserialize MPK: {}", e);
            return std::ptr::null_mut();
        }
    };

    let policy_str = match policy_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert policy C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let policy = match Policy::parse(policy_str) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to parse policy: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    let tau = Tau::new(&policy);
    let mut rng = ark_std::rand::thread_rng();

    let (gt, ct) = encrypt(&mut rng, &mpk, &policy, &tau);

    let mut gt_bytes = Vec::new();
    if gt.serialize_compressed(&mut gt_bytes).is_err() {
        eprintln!("[accless-abe4-rs] Failed to serialize Gt");
        return std::ptr::null_mut();
    }

    let mut ct_bytes = Vec::new();
    if ct.serialize_compressed(&mut ct_bytes).is_err() {
        eprintln!("[accless-abe4-rs] Failed to serialize Ciphertext");
        return std::ptr::null_mut();
    }

    let output = EncryptOutput {
        gt: general_purpose::STANDARD.encode(&gt_bytes),
        ciphertext: general_purpose::STANDARD.encode(&ct_bytes),
    };

    let output_json = match serde_json::to_string(&output) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to serialize output to JSON: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    match CString::new(output_json) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to create CString for output: {}",
                e
            );
            std::ptr::null_mut()
        }
    }
}

/// # Description
///
/// FFI wrapper for the CP-ABE decryption function.
///
/// This function takes a base64-encoded user secret key, a global identifier,
/// a policy string, and a base64-encoded ciphertext. It attempts to decrypt
/// the ciphertext to recover the symmetric key.
///
/// # Arguments
///
/// * `usk_b64`: A C-style string containing the base64-encoded user secret key.
/// * `gid`: A C-style string containing the global identifier of the user.
/// * `policy_str`: A C-style string containing the policy string.
/// * `ct_b64`: A C-style string containing the base64-encoded ciphertext.
///
/// # Returns
///
/// A C-style string containing the base64-encoded symmetric key if decryption
/// is successful, or a null pointer otherwise.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn decrypt_abe4(
    usk_b64: *const c_char,
    gid: *const c_char,
    policy_str: *const c_char,
    ct_b64: *const c_char,
) -> *mut c_char {
    let usk_b64_cstr = unsafe { CStr::from_ptr(usk_b64) };
    let gid_cstr = unsafe { CStr::from_ptr(gid) };
    let policy_cstr = unsafe { CStr::from_ptr(policy_str) };
    let ct_b64_cstr = unsafe { CStr::from_ptr(ct_b64) };

    let usk_b64_str = match usk_b64_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert USK C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let usk_bytes = match general_purpose::STANDARD.decode(usk_b64_str) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to decode USK from base64: {}", e);
            return std::ptr::null_mut();
        }
    };

    let usk: USK = match USK::deserialize_compressed(&usk_bytes[..]) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to deserialize USK: {}", e);
            return std::ptr::null_mut();
        }
    };

    let policy_str_rs = match policy_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert policy C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let policy = match Policy::parse(policy_str_rs) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to parse policy: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    let tau = Tau::new(&policy);

    let user_attrs = usk.get_user_attributes();
    let iota = Iota::new(&user_attrs);

    let ct_b64_str = match ct_b64_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert Ciphertext C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let ct_bytes = match general_purpose::STANDARD.decode(ct_b64_str) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to decode Ciphertext from base64: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let ct: Ciphertext = match Ciphertext::deserialize_compressed(&ct_bytes[..]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[accless-abe4-rs] Failed to deserialize Ciphertext: {}", e);
            return std::ptr::null_mut();
        }
    };

    let gid_str = match gid_cstr.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[accless-abe4-rs] Failed to convert GID C string to Rust string: {}",
                e
            );
            return std::ptr::null_mut();
        }
    };

    let result = decrypt(&usk, gid_str, &iota, &tau, &policy, &ct);

    match result {
        Some(gt) => {
            let mut gt_bytes = Vec::new();
            if gt.serialize_compressed(&mut gt_bytes).is_err() {
                eprintln!("[accless-abe4-rs] Failed to serialize Gt");
                return std::ptr::null_mut();
            }
            let gt_b64 = general_purpose::STANDARD.encode(&gt_bytes);
            match CString::new(gt_b64) {
                Ok(s) => s.into_raw(),
                Err(e) => {
                    eprintln!("[accless-abe4-rs] Failed to create CString for Gt: {}", e);
                    std::ptr::null_mut()
                }
            }
        }
        None => {
            eprintln!("[accless-abe4-rs] Decryption returned None");
            std::ptr::null_mut()
        }
    }
}

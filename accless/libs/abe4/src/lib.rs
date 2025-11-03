mod curve;
mod hashing;
pub mod policy;
pub mod scheme;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::engine::{Engine as _, general_purpose};
pub use curve::Gt;
pub use policy::{Policy, UserAttribute};
pub use scheme::{decrypt, encrypt, iota, keygen, setup, tau};
use scheme::{
    iota::Iota,
    tau::Tau,
    types::{Ciphertext, MPK, MSK, USK},
};
use serde::{Deserialize, Serialize};
use std::{
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

#[derive(Serialize, Deserialize)]
struct SetupOutput {
    msk: String,
    mpk: String,
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setup_abe4(auths_json: *const c_char) -> *mut c_char {
    let auths_cstr = unsafe { CStr::from_ptr(auths_json) };

    let auths: Vec<String> = serde_json::from_str(auths_cstr.to_str().unwrap()).unwrap();
    let auths_ref: Vec<&str> = auths.iter().map(|s| s.as_str()).collect();
    let mut rng = ark_std::rand::thread_rng();

    let (msk, mpk) = setup(&mut rng, &auths_ref);

    let mut msk_bytes = Vec::new();
    msk.serialize_compressed(&mut msk_bytes).unwrap();

    let mut mpk_bytes = Vec::new();
    mpk.serialize_compressed(&mut mpk_bytes).unwrap();

    let output = SetupOutput {
        msk: general_purpose::STANDARD.encode(&msk_bytes),
        mpk: general_purpose::STANDARD.encode(&mpk_bytes),
    };

    let output_json = serde_json::to_string(&output).unwrap();
    CString::new(output_json).unwrap().into_raw()
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

    let msk_bytes = general_purpose::STANDARD
        .decode(msk_b64_cstr.to_str().unwrap())
        .unwrap();
    let msk: MSK = MSK::deserialize_compressed(&msk_bytes[..]).unwrap();

    let user_attrs: Vec<UserAttribute> =
        serde_json::from_str(user_attrs_cstr.to_str().unwrap()).unwrap();

    let iota = Iota::new(&user_attrs);
    let mut rng = ark_std::rand::thread_rng();

    let usk = keygen(
        &mut rng,
        gid_cstr.to_str().unwrap(),
        &msk,
        &user_attrs,
        &iota,
    );

    let mut usk_bytes = Vec::new();
    usk.serialize_compressed(&mut usk_bytes).unwrap();

    let usk_b64 = general_purpose::STANDARD.encode(&usk_bytes);
    CString::new(usk_b64).unwrap().into_raw()
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

    let mpk_bytes = general_purpose::STANDARD
        .decode(mpk_b64_cstr.to_str().unwrap())
        .unwrap();
    let mpk: MPK = MPK::deserialize_compressed(&mpk_bytes[..]).unwrap();

    let policy = Policy::parse(policy_cstr.to_str().unwrap()).unwrap();
    let tau = Tau::new(&policy);
    let mut rng = ark_std::rand::thread_rng();

    let (gt, ct) = encrypt(&mut rng, &mpk, &policy, &tau);

    let mut gt_bytes = Vec::new();
    gt.serialize_compressed(&mut gt_bytes).unwrap();

    let mut ct_bytes = Vec::new();
    ct.serialize_compressed(&mut ct_bytes).unwrap();

    let output = EncryptOutput {
        gt: general_purpose::STANDARD.encode(&gt_bytes),
        ciphertext: general_purpose::STANDARD.encode(&ct_bytes),
    };

    let output_json = serde_json::to_string(&output).unwrap();
    CString::new(output_json).unwrap().into_raw()
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

    let usk_bytes = general_purpose::STANDARD
        .decode(usk_b64_cstr.to_str().unwrap())
        .unwrap();
    let usk: USK = USK::deserialize_compressed(&usk_bytes[..]).unwrap();

    let policy = Policy::parse(policy_cstr.to_str().unwrap()).unwrap();
    let tau = Tau::new(&policy);

    let user_attrs = usk.get_user_attributes();
    let iota = Iota::new(&user_attrs);

    let ct_bytes = general_purpose::STANDARD
        .decode(ct_b64_cstr.to_str().unwrap())
        .unwrap();
    let ct: Ciphertext = Ciphertext::deserialize_compressed(&ct_bytes[..]).unwrap();

    let result = decrypt(&usk, gid_cstr.to_str().unwrap(), &iota, &tau, &policy, &ct);

    match result {
        Some(gt) => {
            let mut gt_bytes = Vec::new();
            gt.serialize_compressed(&mut gt_bytes).unwrap();
            let gt_b64 = general_purpose::STANDARD.encode(&gt_bytes);
            CString::new(gt_b64).unwrap().into_raw()
        }
        None => std::ptr::null_mut(),
    }
}

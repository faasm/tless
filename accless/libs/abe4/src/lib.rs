mod curve;
mod hashing;
mod policy;
mod scheme;

// -------------------------------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------------------
// FFI
// -------------------------------------------------------------------------------------------------
use ark_serialize::CanonicalSerialize;
use base64::engine::{Engine as _, general_purpose};
pub use curve::Gt;
pub use policy::{Policy, UserAttribute};
pub use scheme::{decrypt, encrypt, iota, keygen, setup, tau};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

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

//! This build file generates a file with optionally-injected certificates from
//! (one or different) attestation services and hard-codes them into the JWT
//! library.
use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dest = out_dir.join("src").join("generated_x5c_certs.rs");

    // Optional env var with a directory path to one or more PEM files.
    let cert_dir = env::var("ACCLESS_AS_CERT_DIR").ok();

    let mut entries = String::new();
    if let Some(path) = cert_dir
        && !path.is_empty()
    {
        // Rebuild if that directory changes
        println!("cargo:rerun-if-changed={path}");
        // For each entry in the directory, if it is a .pem file, add it to
        // the list of certificates to embed in the binary.
        for dir_entry in fs::read_dir(path).unwrap() {
            let file_path = dir_entry.unwrap().path();
            if file_path.is_file() {
                let file_path_str = file_path.to_str().unwrap();
                if file_path_str.ends_with(".pem") && !file_path_str.ends_with("key.pem") {
                    entries.push_str(&format!("    include_str!(r\"{file_path_str}\"),\n"));
                }
            }
        }
    }

    let contents = format!(
        "/// Auto-generated; do not edit.\n\
         #[rustfmt::skip]\n\
         pub static INJECTED_X5C_CERTS: &[&str] = &[\n{entries}];\n"
    );

    fs::write(&dest, contents).unwrap();

    // Re-run build script if env var changes
    println!("cargo:rerun-if-env-changed=ACCLESS_AS_CERT_DIR");
}

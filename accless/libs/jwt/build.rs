///! This build file generates a file with optionally-injected certificates from (one or different)
///! attestation services.

use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dest = out_dir.join("src").join("generated_x5c_certs.rs");

    // Optional env var with path to a PEM file.
    let cert_path = env::var("ACCLESS_AS_CERT_PEM").ok();

    // In the furutre we could add more certificates here.
    let mut entries = String::new();
    if let Some(path) = cert_path {
        if !path.is_empty() {
            // Rebuild if that file changes
            println!("cargo:rerun-if-changed={path}");
            // Add an entry to the slice using include_str! on that path
            entries.push_str(&format!("    include_str!(r\"{path}\"),\n"));
        }
    }

    // You can add more entries here in the future if you want more dynamic certs.
    // e.g. read a list of paths from another env var, loop, etc.

    let contents = format!(
        "/// Auto-generated; do not edit.\n\
         pub static INJECTED_X5C_CERTS: &[&str] = &[\n{entries}];\n"
    );

    fs::write(&dest, contents).unwrap();

    // Re-run build script if env var changes
    println!("cargo:rerun-if-env-changed=ACCLESS_AS_CERT_PEM");
}

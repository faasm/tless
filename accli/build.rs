//! This build.rs file parses cargo's metadata and exposes an environment
//! variable that can be consumend in the accli crate to get the absolute path
//! of the workspace root, independently on whether the project is being invoked
//! as an individual package or from the workspace itself.

use serde::Deserialize;
use std::{env, process::Command};

// A minimal struct to deserialize only the `workspace_root` field
#[derive(Deserialize)]
struct Metadata {
    workspace_root: String,
}

fn main() {
    // Tell Cargo to rerun this script if build.rs changes.
    println!("cargo:rerun-if-changed=build.rs");

    // Get the path to the cargo executable.
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    // Run `cargo metadata`.
    let output = Command::new(cargo)
        .arg("metadata")
        .arg("--format-version=1")
        .arg("--no-deps") // We don't need dependency info, making this faster
        .output()
        .expect("Failed to run cargo metadata");

    if !output.status.success() {
        panic!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Parse the JSON output
    let metadata: Metadata =
        serde_json::from_slice(&output.stdout).expect("Failed to parse cargo metadata");

    // Set the environment variable for the crate
    println!(
        "cargo:rustc-env=ACCLESS_ROOT_DIR={}",
        metadata.workspace_root
    );
}

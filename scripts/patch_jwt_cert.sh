#!/bin/bash

# This script patches the known-good X509 certificate in the JWT parsing
# library after we deploy one instance of the attribute-providing-service.
# The service's certificate depends on the IP of where it is deployed, and
# it must be hard-coded inside the function code (for correct measurement).
# This file patches the source code once we have the deployed the service.

set -euo pipefail

# Get directories
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."

# Define file paths
CERT_FILE="${PROJ_ROOT}/attestation-service/certs/cert.pem"
RUST_FILE="${PROJ_ROOT}/accless/libs/jwt/src/lib.rs"

# Define markers
START_MARKER="// BEGIN: AUTO-INJECTED CERT"
END_MARKER="// END: AUTO-INJECTED CERT"

if [[ ! -f "${CERT_FILE}" ]]; then
    echo "accless: patch: error: Certificate file not found at ${CERT_FILE}"
    echo "accless: patch: please run 'attestation-service/bin/gen_keys.sh' first."
    exit 1
fi

if [[ ! -f "${RUST_FILE}" ]]; then
    echo "accless: patch: error: JWT library file not found at ${RUST_FILE}"
    exit 1
fi

echo "accless: patch: Reading new certificate from ${CERT_FILE}"

# Read the certificate and format it as a Rust raw string literal
# We use awk to wrap the file content in `r#"` and `"#,\n`
NEW_CERT_BLOCK=$(awk 'BEGIN {print "r#\""} {print} END {print "\"#,"}' "${CERT_FILE}")

# Use sed to replace the block between the markers
# This command finds the block, including the marker lines, and replaces it
# with the markers *plus* the new certificate block.
sed -i.bak "/${START_MARKER}/,/${END_MARKER}/c\\
${START_MARKER}\
${NEW_CERT_BLOCK}\
${END_MARKER}\
" "${RUST_FILE}"

# Remove the backup file created by sed
rm -f "${RUST_FILE}.bak"

echo "accless: patch: Successfully patched ${RUST_FILE} with new certificate."

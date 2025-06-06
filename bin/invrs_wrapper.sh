#!/bin/bash
set -e

source ./bin/workon.sh

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."
RUST_ROOT="${PROJ_ROOT}/invrs"

cargo run --release --manifest-path ${RUST_ROOT}/Cargo.toml -q -- "$@"

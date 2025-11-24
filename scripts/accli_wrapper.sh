#!/bin/bash
set -e

source ./scripts/workon.sh

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "cargo not found in PATH. Attempting to source $HOME/.cargo/env"
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    else
        echo "Error: $HOME/.cargo/env not found. Please install Rust or ensure it's correctly configured."
        exit 1
    fi

    # Check again after sourcing
    if ! command -v cargo &> /dev/null; then
        echo "Error: cargo still not found after sourcing $HOME/.cargo/env. Please ensure Rust is installed and configured correctly."
        exit 1
    fi
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."
RUST_ROOT="${PROJ_ROOT}/invrs"

cargo run --release -p accli -q -- "$@"

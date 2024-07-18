#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."
RUST_ROOT="${PROJ_ROOT}/invrs"

pushd ${PROJ_ROOT}>>/dev/null

# ----------------------------
# Environment vars
# ----------------------------

export VERSION=$(cat ${PROJ_ROOT}/VERSION)
export PS1="(exp-tless) $PS1"

alias invrs="cargo run --manifest-path ${RUST_ROOT}/Cargo.toml -q --"

# -----------------------------
# Splash
# -----------------------------

echo ""
echo "----------------------------------"
echo "TLess Experiments CLI"
echo "Version: ${VERSION}"
echo "----------------------------------"
echo ""

popd >> /dev/null

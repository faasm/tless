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
source ${PROJ_ROOT}/bin/env.sh

alias invrs="cargo run --manifest-path ${RUST_ROOT}/Cargo.toml -q --"

# ----------------------------
# Python deps
# ----------------------------

VENV_PATH=${PROJ_ROOT}/venv

if [ ! -d ${VENV_PATH} ]; then
    ${PROJ_ROOT}/bin/create_venv.sh
fi

export VIRTUAL_ENV_DISABLE_PROMPT=1
source ${VENV_PATH}/bin/activate


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

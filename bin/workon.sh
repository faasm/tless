#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."
RUST_ROOT="${PROJ_ROOT}/invrs"

pushd ${PROJ_ROOT}>>/dev/null

# ----------------------------
# Environment vars
# ----------------------------

export PROJ_ROOT=${PROJ_ROOT}
export TLESS_VERSION=$(cat ${PROJ_ROOT}/VERSION)
export PS1="(tless) $PS1"
source ${PROJ_ROOT}/bin/env.sh

# alias tlessctl="cargo run --manifest-path ${RUST_ROOT}/Cargo.toml -q --"
alias invrs="cargo run --release --manifest-path ${RUST_ROOT}/Cargo.toml -q --"

# ----------------------------
# Knative vars (TODO FIXME consider changing)
# ----------------------------

export COCO_SOURCE=~/git/coco-serverless/coco-serverless
export KUBECONFIG=${COCO_SOURCE}/.config/kubeadm_kubeconfig
alias k9s=${COCO_SOURCE}/bin/k9s
alias kubectl=${COCO_SOURCE}/bin/kubectl

# ----------------------------
# Faasm vars
# ----------------------------

export FAASM_INI_FILE=${PROJ_ROOT}/faasm.ini
# TODO: update me
export FAASM_VERSION=0.28.0

# ----------------------------
# APT deps
# ----------------------------

sudo apt install -y \
    libfontconfig1-dev \
    libssl-dev \
    pkg-config > /dev/null 2>&1

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
echo "Version: ${TLESS_VERSION}"
echo "Project root: ${PROJ_ROOT}"
echo "----------------------------------"
echo ""

popd >> /dev/null

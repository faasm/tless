#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."

pushd ${PROJ_ROOT}>>/dev/null

# ----------------------------
# Environment vars
# ----------------------------

export PROJ_ROOT=${PROJ_ROOT}
export TLESS_VERSION=$(cat ${PROJ_ROOT}/VERSION)
export PS1="(accless) $PS1"
source ${PROJ_ROOT}/scripts/env.sh

# ----------------------------
# Git
# ----------------------------

git config --local core.hooksPath "${PROJ_ROOT}/config/githooks"

# ----------------------------
# Aliases
# ----------------------------

alias accli="cargo run --release -p accli -q --"

# ----------------------------
# Knative vars (TODO FIXME consider changing)
# ----------------------------

export COCO_SOURCE=~/git/sc2-sys/deploy
export KUBECONFIG=${COCO_SOURCE}/.config/kubeadm_kubeconfig
alias k9s=${COCO_SOURCE}/bin/k9s
alias kubectl=${COCO_SOURCE}/bin/kubectl

# ----------------------------
# Faasm vars
# ----------------------------

# This is the path in the SGX-enabled machine we use for the experiments
export FAASM_INI_FILE=/home/tless/git/faasm/faasm/faasm.ini
export FAASM_VERSION=0.33.0

# ----------------------------
# APT deps
# ----------------------------

source ${THIS_DIR}/apt.sh

# ----------------------------
# Python deps
# ----------------------------

if [[ -z "$ACCLESS_DOCKER" ]]; then
    VENV_PATH="${PROJ_ROOT}/venv-bm"
else
    VENV_PATH="${PROJ_ROOT}/venv"
fi

if [ ! -d ${VENV_PATH} ]; then
    ${PROJ_ROOT}/scripts/create_venv.sh
fi

export VIRTUAL_ENV_DISABLE_PROMPT=1
source ${VENV_PATH}/bin/activate


# -----------------------------
# Splash
# -----------------------------

echo ""
echo "----------------------------------"
echo "Accless CLI"
echo "Version: ${TLESS_VERSION}"
echo "Project root: ${PROJ_ROOT}"
echo "----------------------------------"
echo ""

popd >> /dev/null

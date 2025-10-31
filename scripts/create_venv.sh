#!/bin/bash

set -e

THIS_DIR=$(dirname $(readlink -f $0))
PROJ_ROOT=${THIS_DIR}/..
VENV_PATH="${PROJ_ROOT}/venv"

PIP=${VENV_PATH}/bin/pip3

function pip_cmd {
    source ${VENV_PATH}/bin/activate && ${PIP} "$@"
}

pushd ${PROJ_ROOT} >> /dev/null

if [ ! -d ${VENV_PATH} ]; then
    python3 -m venv ${VENV_PATH}
fi

pip_cmd install -U pip setuptools wheel
pip_cmd install -r requirements.txt

# If deployed inside a container, also install `faasmtools` for WASM
# cross-compilation. Note that this path is hard-coded in:
# ./config/docker/accless-experiments.dockerfile
if [ -d /code/faasm-examples/cpp ]; then
    pip_cmd install /code/faasm-examples/cpp
fi

popd >> /dev/null

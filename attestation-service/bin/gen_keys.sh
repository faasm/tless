#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."

URL="${AS_URL:-"127.0.0.1"}"
CERTS_DIR=${AS_CERTS_DIR:-"${PROJ_ROOT}/certs"}

if [[ "$1" != "--force" ]]; then
  echo "WARNING: this script overwrites the keys in ${CERTS_DIR},"
  echo "WARNING: these keys and certificates are baked into the enclaves"
  echo "WARNING: if you know what you are doing, re-run the script with --force"
  exit 1
fi

mkdir -p ${CERTS_DIR}
openssl \
    req -x509 \
    -newkey rsa:4096 -keyout "${CERTS_DIR}/key.pem" \
    -out "${CERTS_DIR}/cert.pem" \
    -days 365 -nodes \
    -subj "/CN=${URL}" \
     -addext "subjectAltName = IP:${URL}" > /dev/null \
    && echo "accless: as: generated private key and certs at: ${CERTS_DIR}" \
    || echo "accless: as: error generating private key and certificates"

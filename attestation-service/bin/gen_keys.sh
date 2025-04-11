#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."

URL=${AS_URL:-"127.0.0.1"}
CERTS_DIR=${AS_CERTS_DIR:-"${PROJ_ROOT}/certs"}

mkdir -p ${CERTS_DIR}
openssl \
    req -x509 \
    -newkey rsa:4096 -keyout "${CERTS_DIR}/key.pem" \
    -out "${CERTS_DIR}/cert.pem" \
    -days 365 -nodes \
    -subj "/CN=${URL}" > /dev/null \
    && echo "accless: as: generated private key and certs at: ${CERTS_DIR}" \
    || echo "accless: as: error generating private key and certificates"

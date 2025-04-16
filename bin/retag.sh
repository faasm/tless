#!/bin/bash


# Check if it's set and not empty
if [ -z "${!ACCLESS_VERSION}" ]; then
  echo "Environment variable '$ACCLESS_VERSION' is not set or is empty."
  exit 1
fi

docker tag ghcr.io/faasm/accless-knative-worker:0.5.0 sc2cr.io/accless-knative-worker:${ACCLESS_VERSION}
docker push sc2cr.io/accless-knative-worker:${ACCLESS_VERSION}

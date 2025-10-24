# Ligthweight container image to use as worker runtime in CC-Knative
ARG TLESS_VERSION
FROM ghcr.io/faasm/accless-experiments:${TLESS_VERSION:-d34d} AS build

FROM ubuntu:24.04
LABEL org.opencontainers.image.source=https://github.com/faasm/tless

# Some built shared libraries depend on the absolute path
COPY --from=build \
    /code/tless/workflows/build-native/_deps/azguestattestation-build/AttestationClient/libazguestattestation.so \
    /code/tless/workflows/build-native/_deps/azguestattestation-build/AttestationClient/libazguestattestation.so

# ------------------------------------- Functions ------------------------------

COPY --from=build \
    /code/tless/ubench/build-native \
    /code/tless/ubench/build-native

# ------------------------------------- Workflows ------------------------------

# FINRA
COPY --from=build \
    /code/tless/workflows/target/release/accless-finra-cloudevent-handler \
    /workflows/finra/knative/
COPY --from=build \
    /code/tless/workflows/build-native/finra/ \
    /workflows/build-native/finra
# ML Training
COPY --from=build \
    /code/tless/workflows/target/release/accless-ml-training-cloudevent-handler \
    /workflows/ml-training/knative/
COPY --from=build \
    /code/tless/workflows/build-native/ml-training/ \
    /workflows/build-native/ml-training
# ML Infenrence
COPY --from=build \
    /code/tless/workflows/target/release/accless-ml-inference-cloudevent-handler \
    /workflows/ml-inference/knative/
COPY --from=build \
    /code/tless/workflows/build-native/ml-inference/ \
    /workflows/build-native/ml-inference
# Word Cont
COPY --from=build \
    /code/tless/workflows/target/release/accless-word-count-cloudevent-handler \
    /workflows/word-count/knative/
COPY --from=build \
    /code/tless/workflows/build-native/word-count/ \
    /workflows/build-native/word-count

# Copy libraries we need at runtime
COPY --from=build /usr/local/lib/opencv2/ /usr/local/lib/opencv2
COPY --from=build /lib/x86_64-linux-gnu/ /lib/x86_64-linux-gnu/
COPY --from=build /usr/local/attestationcurl/lib /usr/local/attestationcurl/lib
COPY --from=build /usr/local/attestationssl/lib64 /usr/local/attestationssl/lib64
COPY --from=build /usr/local/attestationtpm2-tss /usr/local/attestationtpm2-tss

# Copy trusted certificates
# TODO: support copying a list in
COPY ./attestation-service/certs/cert.pem /certs/cert.pem

# Set env. vars for runtime
ENV S3_BUCKET=tless \
    S3_HOST=minio \
    S3_PASSWORD=minio123 \
    S3_PORT=9000 \
    S3_USER=minio \
    ACCLESS_AS_URL="https://146.179.4.33:8443" \
    ACCLESS_AS_CERT=/certs/cert.pem

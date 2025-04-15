# Ligthweight container image to use as worker runtime in CC-Knative
ARG TLESS_VERSION
FROM ghcr.io/faasm/accless-experiments:${TLESS_VERSION:-d34d} AS build

FROM ubuntu:22.04
LABEL org.opencontainers.image.source=https://github.com/faasm/experiment-tless

# Some built shared libraries depend on the absolute path
COPY --from=build \
    /code/tless/ubench/build-native \
    /code/tless/ubench/build-native

# ----- Explicitly copy each workflow separately to minimise space -----

# # FINRA
# COPY --from=build \
    #     /code/faasm-examples/workflows/finra/knative/target/ \
    #     /workflows/finra/knative/target
# COPY --from=build \
    #     /code/faasm-examples/workflows/build-native/finra/ \
    #     /workflows/build-native/finra
# # ML Training
# COPY --from=build \
    #     /code/faasm-examples/workflows/ml-training/knative/target/ \
    #     /workflows/ml-training/knative/target
# COPY --from=build \
    #     /code/faasm-examples/workflows/build-native/ml-training/ \
    #     /workflows/build-native/ml-training
# # ML Infenrence
# COPY --from=build \
    #     /code/faasm-examples/workflows/ml-inference/knative/target/ \
    #     /workflows/ml-inference/knative/target
# COPY --from=build \
    #     /code/faasm-examples/workflows/build-native/ml-inference/ \
    #     /workflows/build-native/ml-inference
# # Word Cont
# COPY --from=build \
    #     /code/faasm-examples/workflows/word-count/knative/target/ \
    #     /workflows/word-count/knative/target
# COPY --from=build \
    #     /code/faasm-examples/workflows/build-native/word-count/ \
    #     /workflows/build-native/word-count

# Copy libraries we need at runtime
COPY --from=build /usr/local/lib/opencv2/ /usr/local/lib/opencv2
COPY --from=build /lib/x86_64-linux-gnu/ /lib/x86_64-linux-gnu/
COPY --from=build /usr/local/attestationcurl/lib /usr/local/attestationcurl/lib
COPY --from=build /usr/local/attestationssl/lib64 /usr/local/attestationssl/lib64
COPY --from=build /usr/local/attestationtpm2-tss /usr/local/attestationtpm2-tss

# Set env. vars for runtime
ENV S3_BUCKET=tless \
    S3_HOST=minio \
    S3_PASSWORD=minio123 \
    S3_PORT=9000 \
    S3_USER=minio

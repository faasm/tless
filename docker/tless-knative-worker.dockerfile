# Ligthweight container image to use as worker runtime in CC-Knative
ARG TLESS_VERSION
FROM ghcr.io/coco-serverless/tless-experiments:${TLESS_VERSION:-d34d} AS build

FROM ubuntu:22.04
LABEL org.opencontainers.image.source=https://github.com/faasm/experiment-tless

# Install rust
RUN apt update \
    && apt install -y curl \
    && curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh -s -- -y

COPY --from=build /code/faasm-examples /code/faasm-examples
COPY --from=build /usr/local/lib /usr/local/lib
COPY --from=build /lib/x86_64-linux-gnu/ /lib/x86_64-linux-gnu/

ENV PATH=${PATH}:/root/.cargo/bin
WORKDIR /code/faasm-examples/workflows/build-native

# Ligthweight container image to use as worker runtime in CC-Knative
ARG TLESS_VERSION
FROM faasm.azurecr.io/tless-experiments:${TLESS_VERSION:-d34d} AS build

FROM ubuntu:24.04

COPY --from=build /code/faasm-examples /code/faasm-examples
WORKDIR /code/faasm-examples/build-native

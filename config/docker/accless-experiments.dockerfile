FROM ghcr.io/faasm/cpp-sysroot:0.8.0

# Install rust
ENV RUSTUP_HOME=/opt/rust/rustup
ENV CARGO_HOME=/opt/rust/cargo
ENV PATH=/opt/rust/cargo/bin:$PATH
RUN apt update && apt install -y --no-install-recommends \
        acl \
        build-essential \
        curl \
        gosu \
        libboost-dev \
        sudo \
        wget \
        zlib1g-dev \
    && curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh -s -- -y \
    # Create a group that owns the rust toolchain so that we can share it with
    # our user at run time.
    && groupadd -r rusttool \
    && mkdir -p /opt/rust/rustup /opt/rust/cargo \
    && chown -R root:rusttool /opt/rust \
    && chmod -R g+rwX /opt/rust \
    && find /opt/rust -type d -exec chmod g+s {} +

# Deps for Azure's cVM guest library: OpenSSL + libcurl + TPM2-TSS.
# The versions are taken from the pre-requisite script in the repo, and the
# installation paths are hard-coded in the CMake file:
# https://github.com/faasm/azure-cvm-guest-attestation/blob/main/pre-requisites.sh
RUN wget https://www.openssl.org/source/openssl-3.3.2.tar.gz \
    && tar -C /tmp -xzf openssl-3.3.2.tar.gz \
    && rm -rf openssl-3.3.2.tar.gz \
    && cd /tmp/openssl-3.3.2 \
    && LDFLAGS='-Wl,-R/usr/local/attestationssl/lib64' \
        ./config --prefix=/usr/local/attestationssl --openssldir=/usr/local/attestationssl \
    && make -j$(nproc) \
    && make install_sw \
    && wget https://curl.se/download/curl-8.5.0.tar.gz --no-check-certificate \
    && tar -C /tmp -xzf curl-8.5.0.tar.gz \
    && rm -rf curl-8.5.0.tar.gz && cd /tmp/curl-8.5.0 \
    && env \
        PKG_CONFIG_PATH=/usr/local/attestationssl/lib64/pkgconfig \
        LDFLAGS='-Wl,-R/usr/local/attestationssl/lib64' \
        ./configure \
        --without-zstd \
        --with-openssl \
        --prefix=/usr/local/attestationcurl \
    && make -j$(nproc) \
    && make install \
    && rm -rf /opt/tpm2-tss \
    && apt update \
    && apt install -y \
        autoconf-archive \
        libfmt-dev \
        libgcrypt-dev \
        libjson-c-dev \
        uuid-dev \
    && git clone https://github.com/tpm2-software/tpm2-tss.git /opt/tpm2-tss \
    && git config --global --add safe.directory /opt/tpm2-tss \
    && cd /opt/tpm2-tss \
    && ./bootstrap \
    && env \
        PKG_CONFIG_PATH=/usr/local/attestationcurl/lib/pkgconfig:/usr/local/attestationssl/lib64/pkgconfig \
        LDFLAGS='-Wl,-R/usr/local/attestationssl/lib64 -Wl,-R/usr/local/attestationcurl/lib' \
        CPPFLAGS='-I/usr/local/attestationcurl/include' \
        ./configure --prefix=/usr/local/attestationtpm2-tss \
    && make -j$(nproc) \
    && make install \
    && rm -rf /opt/tpm2-tss

# Build specific libraries we need
ARG EXAMPLES_DIR=/code/faasm-examples
RUN rm -rf /code \
    && mkdir -p /code \
    && cd /code \
    # Checkout to examples repo to a specific commit
    && git clone https://github.com/faasm/examples ${EXAMPLES_DIR} \
    && cd ${EXAMPLES_DIR} \
    && git checkout 3cd09e9cf41979fe73c8a9417b661ba08b5b3a75 \
    && git submodule update --init -f cpp \
    # Build specific CPP libs
    && cd ${EXAMPLES_DIR}/cpp \
    && ./bin/inv_wrapper.sh libfaasm --clean \
    && git submodule update --init ./third-party/zlib \
    && ./bin/inv_wrapper.sh zlib \
    && cd ${EXAMPLES_DIR} \
    && git submodule update --init ./examples/opencv \
    && ./bin/inv_wrapper.sh \
        opencv opencv --native \
    # Add shared group ownership to faasm code.
    && groupadd -r faasm \
    && mkdir -p ${EXAMPLES_DIR} \
    # maybe /code needs it too TODO delete me
    && chown -R root:faasm ${EXAMPLES_DIR} \
    && chmod -R g+rwX ${EXAMPLES_DIR} \
    # make directories setgid so new stuff inherits the group TODO delete me
    && find /code -type d -exec chmod g+s {} + \
    && setfacl -R -m g:faasm:rwX ${EXAMPLES_DIR} \
    && setfacl -R -d -m g:faasm:rwX ${EXAMPLES_DIR}

# Prepare repository structure
ARG ACCLESS_VERSION
RUN cd /code \
    && git clone -b v${ACCLESS_VERSION} https://github.com/faasm/tless /code/accless \
    && cd /code/accless \
    && source ./scripts/workon.sh

# Build workflow code (WASM for Faasm + Native for Knative)
# ENV PATH=${PATH}:/root/.cargo/bin
ENV ACCLESS_DOCKER=on
# RUN cd /code/accless \
    #     # Activate faasmtools
#     && source /code/faasm-examples/cpp/bin/workon.sh \
    #     && python3 ./ubench/build.py \
    #     && python3 ./workflows/build.py

WORKDIR /code/accless
COPY scripts/docker/entrypoint.sh /usr/local/bin/docker_entrypoint.sh
RUN chmod +x /usr/local/bin/docker_entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker_entrypoint.sh"]

CMD ["/bin/bash", "-c"]

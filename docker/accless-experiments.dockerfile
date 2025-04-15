# We inherit from the examples repo because it is likely that we want to use
# off-the-shelve examples like tensorflow
FROM faasm.azurecr.io/examples-build:0.6.0_0.4.0

# Install rust
RUN rm -rf /root/.rustup \
    && curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh -s -- -y \
    && rustup target add wasm32-wasip1

# Prepare repository structure
RUN rm -rf /code \
    && mkdir -p /code \
    && cd /code \
    # Checkout to examples repo to a specific commit
    && git clone https://github.com/faasm/examples /code/faasm-examples \
    && cd /code/faasm-examples \
    && git checkout b3beb98403ddf2a21255e03a1c894d9c60a287a8 \
    && git submodule update --init -f cpp \
    && pip3 install /code/faasm-examples/cpp \
    && git clone https://github.com/faasm/tless /code/tless

# Build specific libraries we need
RUN cd /code/faasm-examples/cpp \
    # Build specific CPP libs
    && ./bin/inv_wrapper.sh libfaasm --clean \
    && git submodule update --init ./third-party/zlib \
    && ./bin/inv_wrapper.sh zlib \
    && cd /code/faasm-examples \
    && git submodule update --init ./examples/opencv \
    && git submodule update --init ./examples/rabe \
    && git submodule update --init ./examples/tless-jwt \
    && ./bin/inv_wrapper.sh \
        jwt \
        opencv opencv --native \
        rabe rabe --native

# Build workflow code (WASM for Faasm + Native for Knative)
ENV PATH=${PATH}:/root/.cargo/bin
RUN cd /code/tless \
    && python3 ./ubench/build.py
    # && python3 ./workflows/build.py

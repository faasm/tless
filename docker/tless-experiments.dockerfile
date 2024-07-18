# Build the experiments' code
FROM faasm.azurecr.io/examples-build:0.5.0_0.4.0 as build

# Prepare repository structure
RUN rm -rf /code \
    && mkdir -p /code \
    && cd /code \
    # Checkout to examples repo to a specific commit
    && git clone https://github.com/faasm/examples /code/faasm-examples \
    && cd /code/faasm-examples \
    && git checkout 428a11c80263b82ea8a83157205c4ef0eceab979 \
    && git submodule update --init -f cpp \
    # Checkout this repo to a specific commit
    && git clone https://github.com/faasm/experiment-tless /code/experiment-tless \
    && cp /code/experiment-tless/workflows /code/faasm-examples/ \
    && mv /code/faasm-examples/workflows/build.py /code/faasm-examples/build_workflows.py

# Build WASM code
RUN cd /code/faasm-examples \
    # Install faasmtools
    && ./bin/create_venv.sh \
    && source ./venv/bin/activate \

# Prepare the runtime to run the native experiments
# TODO

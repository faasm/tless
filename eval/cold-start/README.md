# Overhead of Access Control to Cold-Starts

In this experiment we measure the overheads that Accless access control
mechanisms introduce to cold-starts. It is a simple breakdown of the cost
of each individual component in Accless.

The set-up is simple: we invoke a no-op function that just releases a secret,
and we measure the end-to-end time start-up time, as well as the time elapsed
in each different step.

## Deploy

### SGX-Faasm

First, make sure you have deployed [SGX-Faasm](../../docs/sgx_faasm.md). Then,
SSH into the SGX VM using: `invrs azure sgx-faasm ssh`.

Once inside, you can cross-compile the micro-benchmark functions:

```bash
invrs docker cli
cd /code/tless/ubench
python3 build.py
```

you may exit the container, and copy the WASM file into the Faasm sysroot:

```bash
sudo mkdir -p ~/git/faasm/faasm/dev/faasm-local/wasm/accless/ubench-cold-start
sudo cp ~/git/faasm/tless/ubench/build-wasm/accless-ubench-cold-start ~/git/faasm/faasm/dev/faasm-local/wasm/accless/ubench-cold-start/function.wasm
```

lastly, you may generate the machine code, and run the function from the Faasm
CLI. Before, running with `ACCLES_ENABLED=on`, however, you will have to
upload the workflow DAG used in the example:

```bash
invrs dag upload word-count ./workflows/word-count/accless.yaml
```

then, do:

```bash
faasmctli cli.faasm
inv codegen accless ubench-cold-start
[TLESS_ENABLED=on] inv run accless ubench-cold-start
```

you should see a series of print messages that correspond to the times that
we include in the Table in the evaluation.

TODO: automate, and take averages?

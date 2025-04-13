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

you may exit the container, and upload the WASM file to the Faasm cluster:

```bash
faasmctl upload accless ubench-cold-start  ~/git/faasm/tless/ubench/build-wasm/accless-ubench-cold-start
```

as well as the demo workflow DAG,

```bash
invrs dag upload word-count ./workflows/word-count/accless.yaml
```

and you may invoke it with:

```bash
faasmctl invoke accless ubench-cold-start
```

To reproduce the number in the table you will have to re-compile the function:

```bash
invrs docker cli
cd /code/tless/ubench
# TODO: pass CMake falg to WASM
python3 build.py --time
```

then flush (`faasmctl flush.hosts`), re-upload and re-invoke. You should see a
series of print messages that correspond to the times that we include in the
Table in the evaluation.

TODO: automate, and take averages?

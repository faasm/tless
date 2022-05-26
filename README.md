# TLess [![Tests](https://github.com/faasm/tless/workflows/Tests/badge.svg?branch=main)](https://github.com/faasm/tless/actions)  [![License](https://img.shields.io/github/license/faasm/tless.svg)](https://github.com/faasm/tless/blob/main/LICENSE.md)  [![Release](https://img.shields.io/github/release/faasm/tless.svg)](https://github.com/faasm/tless/releases/)  [![Contributors](https://img.shields.io/github/contributors/faasm/tless.svg)](https://github.com/faasm/tless/graphs/contributors/)

TLess is a confidential serverless runtime.

TLess builds on the [Faasm](https://github.com/faasm/faasm) serverless runtime
for lightweight multi-tenant isolation. TLess uses Trusted Execution
Environments (TEEs) for inter-application isolation, and WebAssembly for
inter-function isolation at low cost.

TLess combines individual function's attestation proofs to guarantee execution
integrity and confidentiality of arbitrary serverless applications expressed
by means of a call graph.

TLess uses Intel SGX as a TEE and Azure's Attestation Service for remote
attestation of SGX enclaves. If your TLess cluster also runs on Azure, you
can benefit of high-performance remote attestation using Intel DCAP.

## Quick start

Update submodules:

```bash
git submodule update --init --recursive
```

You may run a TLess cluster locally using `docker-compose` both in simulation
or hardware mode. To check if your machine supports SGX, you may run:

```bash
./bin/cli.sh tless
inv dev.cc detect_sgx
detect_sgx
```

Then, run either in simulation (default) or hardware mode:

```bash
SGX_MODE=Hardware docker-compose up -d --scale worker=2 nginx
```

To compile, upload and invoke a C++ function using this local cluster you can
use the [faasm/cpp](https://github.com/faasm/cpp) container:

```bash
docker-compose run cpp /bin/bash

# Compile the demo function
inv func demo hello

# Upload the demo "hello" function
inv func.upload demo hello

# Invoke the function
inv func.invoke demo hello
```

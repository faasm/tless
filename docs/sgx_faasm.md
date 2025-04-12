# SGX-Faasm

## Deploy

For the time being, we deploy SGX-Faasm on an SGXv2 VM on Azure, and deploy
a Faasm compose cluster in there. In the future we could consider deploying
directly on top of AKS.

```bash
invrs azure sgx-faasm create
invrs azure sgx-faasm provision
```

## Running a sample function

To get started with SGX-Faasm, you can try and run a simple function that
(optionally) uses Accless' access control.

First, SSH into the SGX VM:

```bash
invrs azure sgx-faasm ssh
# ssh
```

now you must cross-compile our simple function to WebAssembly using our
Accless-aware WASM cross-compilation toolchain.

```bash
cd git/faasm/tless
```



### Faasm Baselines

To deploy the Faasm-based baselines - Faasm, Sgx-Faasm, and TLess-Faasm -
just run the following:

```bash
# TODO: move to k8s when it works
faasmctl deploy.compose --workers=4
```

TODO

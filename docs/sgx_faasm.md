# SGX-Faasm

SGX-Faasm is a port of the [Faasm](https://github.com/faasm/faasm) serverless
runtime to execute serverless functions (inside WASM modules) inside SGX
enclaves and, optionally, leverage Accless for access control.

We had to modify Faasm quite extensively, but all our modifications are
upstreamed and cover mostly what is under the `src/enclave` directory.

## Deploy

For the time being, we deploy SGX-Faasm on an SGXv2 VM on Azure, and deploy
a Faasm compose cluster in there. In the future we could consider deploying
directly on top of AKS.

To create the Azure resources to run SGX-Faasm you may run:

```bash
invrs azure sgx-faasm create
invrs azure sgx-faasm provision
```

then, for each variant of Faasm follow the coresponding instructions:
* [Faasm](#faasm) - vanilla  Faasm.
* [SGX-Faasm](#sgx-faasm) - Faasm on top of SGX, no access control.
* [Accless-Faasm](#sgx-faasm) - Faasm on top of SGX with access control.

### Faasm

```bash
export FAASM_WASM_VM=wamr
faasmctl deploy.compose --mount-source . --workers=1
faasmctl cli.faasm
inv dev.tools --build Release --sgx Disabled
exit
```

### SGX-Faasm

```bash
export FAASM_ACCLESS_ENABLED=off
export FAASM_WASM_VM=sgx
faasmctl deploy.compose --mount-source . --workers=1
faasmctl cli.faasm
inv dev.tools --build Release --sgx Hardware
exit
```

### Accless-Faasm

```bash
export FAASM_ACCLESS_ENABLED=on
export FAASM_WASM_VM=sgx
export FAASM_ATTESTATION_SERVICE_URL=...
faasmctl deploy.compose --mount-source . --workers=1
faasmctl cli.faasm
inv dev.tools --build Release --sgx Hardware
exit
```

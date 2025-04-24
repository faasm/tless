# SGX-Faasm

TODO(docs): explain SGX-Faasm design

## Deploy

For the time being, we deploy SGX-Faasm on an SGXv2 VM on Azure, and deploy
a Faasm compose cluster in there. In the future we could consider deploying
directly on top of AKS.

```bash
invrs azure sgx-faasm create
invrs azure sgx-faasm provision
```

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

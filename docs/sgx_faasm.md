# SGX-Faasm

## Deploy

For the time being, we deploy SGX-Faasm on an SGXv2 VM on Azure, and deploy
a Faasm compose cluster in there. In the future we could consider deploying
directly on top of AKS.

```bash
invrs azure sgx-faasm create
invrs azure sgx-faasm provision
```

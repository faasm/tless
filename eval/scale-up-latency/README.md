# Scale-Out Latency

## Deploy the experiment

To deploy the baseline follow the corresponding instructions: [SNP-Knative](
../docs/snp_knative.md) or [SGX-Faasm](../../docs/sgx_faasm.md).

## Run the experiment

For each baseline, separately, you may run:

```bash
# In a Knative environment
kubectl apply -f ./k8s/common.yaml
invrs eval scale-up-latency upload-state
invrs eval scale-up-latency run --baseline [knative,snp-knative,accless-knative] [--debug]
...
# Once you are done
kubectl delete namespace accless

# In a Faasm environment
invrs eval scale-up-latency upload-state
invrs eval scale-up-latency upload-wasm
invrs eval scale-up-latency run --baseline [faasm,sgx-faasm,accless-faasm] [--debug]
...
# Once you are done
faasmctl delete
```

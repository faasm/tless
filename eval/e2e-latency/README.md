# End-to-End Workflow Execution Latency

This experiment measures the end-to-end execution latency for each of the
implemented workflows.

## Deploy the experiment

To deploy the baseline follow the corresponding instructions: [SNP-Knative](
../docs/snp_knative.md) or [SGX-Faasm](../../docs/sgx_faasm.md).

## Run the experiment

To run each baseline, separately, you may run:

```bash
# In an SGX-Faasm deployment
kubectl apply -f ./k8s/common.yaml
invrs eval e2e-latency upload-state
invrs eval e2e-latency run --baseline {faasm,sgx-faasm,acc-faasm} [--debug]

# In an SNP-Knative deployment
invrs eval e2e-latency upload-state
invrs eval e2e-latency run --baseline {knative,snp-knative,acc-knative} [--debug]
```

## Plot the results

Once you are done running the experiments and scp-ing the results, you may
run:

```bash
invrs eval e2e-latency plot
```

you should get something like the following:

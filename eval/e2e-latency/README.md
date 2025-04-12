# End-to-End Workflow Execution Latency

This experiment measures the end-to-end execution latency for each of the
implemented workflows.

## Deploy

Each baseline runs in a different set-up on Azure. Intuitively, the process is
always the same:
1. Deploy the baseline: [SGX-Faasm](../../docs/sgx_faasm.md) or [SNP-Knative](../../docs/snp_knative).
2. SSH into the corresponding VM: `invrs azure {sgx-faasm/snp-knative} ssh`
3. Run the `invrs eval` commands from inside the VM in `git/faasm/tless`
4. After the experiment, copy the results: `invrs azure {sgx-faasm/snp-knative} scp-results <EXP_TODO>`

## Run the experiment

To run each baseline, separately, you may run:

```bash
# In an SGX-Faasm deployment
invrs eval e2e-latency run --baseline {faasm,sgx-faasm,acc-faasm} [--debug]

# In an SNP-Knative deployment
invrs eval e2e-latency run --baseline {knative,snp-knative,acc-knative} [--debug]
```

## Plot the results

Once you are done running the experiments and scp-ing the results, you may
run:

```bash
invrs eval e2e-latency plot
```

you should get something like the following:

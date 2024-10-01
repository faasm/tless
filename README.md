# TLess Experiments

This repository hosts the experiments for the TLess project, a system design
for confidential serverless workflows.

We implement TLess on top of two confidential FaaS runtimes representative of
two points in the design space for confidential serverless:
- [Faasm + SGX](https://github.com/faasm/faasm/tree/main/src/enclave): a port
  of the [Faasm](https://github.com/faasm/faasm) to run WASM sandboxes inside SGX.
- [CC-Knative](https:github.com/coco-serverless/coco-serverless): a port of the
  [Knative](https://knative.dev) runtime to run Knative services as container
  functions inside confidential VMs (AMD SEV).

To execute any code snippet in this repository, we will assume that you have
activated your virtual environment:

```bash
source ./bin/workon.sh
```

## Baselines

### Faasm Baselines

To deploy the Faasm-based baselines - Faasm, Sgx-Faasm, and TLess-Faasm -
just run the following:

```bash
# TODO: move to k8s when it works
faasmctl deploy.compose --workers=4
```

### Knative Baselines

To deploy the Knative-based baselines - Knative, CC-Knative, and TLess-Knative -
run the following:

```bash
# TODO
```

## Workflows

This repository implements one different workflow:
- [Word Count](./workflows/word-count/README.md) - Ported from the MapReduce [example](https://github.com/ddps-lab/serverless-faas-workbench/tree/master/aws/cpu-memory/mapreduce) in the FunctionBench paper.

### Progress Summary

| Workflow\Baseline | Faasm | SGX-Faasm | TLess-Faasm | Knative | CC-Knative | TLess-Knative |
|---|---|---|---|---|---|---|
| FINRA | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: |
| ML Training | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: |
| ML Inference | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: |
| Word Count | :heavy_check_mark: | :heavy_check_mark: | :heavy_multiplication_x: | :heavy_check_mark: | :heavy_check_mark: | :heavy_multiplication_x: |

## Experiments

We run the following experiments:
- [End-to-end latency](./eval/e2e-latency/README.md): measures the end-to-end execution latency for each workflow.

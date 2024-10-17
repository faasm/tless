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

## Pre-requisites

Install `rust` and `rust-analyzer`. Then `rustup component add rust-analyzer`.

```bash
# TODO: install this in the background
sudo apt install -y \
  libfontconfig1-dev \
  libssl-dev \
  pkg-config \
```

## Baselines

TLess currently supports being deployed on top of two serverless runtimes,
[Faasm](https://github.com/faasm/faasm) and [Knative](https://knative.dev).

For instructions to deploy each one of them, see:
- [Deploying on top of Faasm](./docs/tless_on_faasm.md)
- [Deploying on top of Knative](./docs/tless_on_knative.md)

## Workflows

This repository implements four different workflows:
- [FINRA](./workflows/finra/README.md) - Based on the AWS FINRA [case study](https://aws.amazon.com/solutions/case-studies/finra-data-validation/).
- [ML Training](./workflows/ml-training/README.md) - Ported from [Orion](https://www.usenix.org/conference/osdi22/presentation/mahgoub) and [RMMap](https://dl.acm.org/doi/abs/10.1145/3627703.3629568).
- [ML Inference](./workflows/ml-inference/README.md) - Ported from [RMMap](https://dl.acm.org/doi/abs/10.1145/3627703.3629568).
- [Word Count](./workflows/word-count/README.md) - Ported from the MapReduce [example](https://github.com/ddps-lab/serverless-faas-workbench/tree/master/aws/cpu-memory/mapreduce) in the FunctionBench paper.

### Progress Summary

| Workflow\Baseline | Faasm | SGX-Faasm | TLess-Faasm | Knative | CC-Knative | TLess-Knative |
|---|---|---|---|---|---|---|
| FINRA | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: | :white_check_mark: | :x: |
| ML Training | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: | :x: |
| ML Inference | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: | :x: |
| Word Count | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: | :white_check_mark: | :x: |

## Experiments

We run the following experiments:
- [End-to-end latency](./eval/e2e-latency/README.md): measures the end-to-end execution latency for each workflow.

<div align="center">
  <h1><code>Accless</code></h1>

  <p>
    <strong>Access Control for Confidential Serverless</strong>
  </p>

  <p>
    <a href="https://github.com/faasm/tless/actions/workflows/checks.yml"><img src="https://github.com/faasm/tless/actions/workflows/checks.yml/badge.svg" alt="Formatting Checks" /></a>
  </p>
  <hr>
</div>

Accless is a serverless access control system for confidential serverless
applications. Accless takes a serverless application specified by a workflow
graph, and derives an access control policy. It then uses
[attribute-based encryption]() to encrypt the code and data for each function
such that it can be decrypted if-and-only-if the function execution context,
including its own roles and its upstream call-stack, pass the access control
policy.

Accless is integrated on top of two existing confidential serverless runtimes:
- [Faasm](https://github.com/faasm/faasm) + SGX: we extend (and upstream) Faasm
to support executing Faaslets inside SGX enclaves.
- [Knative](https://knative.dev) + SNP: we use a port of Knative that can
deploy services inside confidential VMs (as pods in k8s) based on [SC2](
https://github.com/sc2-sys).

To execute any code snippet in this repository, we will assume that you have
activated your virtual environment:

```bash
source ./bin/workon.sh
```

## Pre-requisites

Install `rust` and `rust-analyzer`. Then `rustup component add rust-analyzer`.

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
| FINRA | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| ML Training | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| ML Inference | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Word Count | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |

## Experiments

We run the following experiments:
- [End-to-end latency](./eval/e2e-latency/README.md): measures the end-to-end execution latency for each workflow.

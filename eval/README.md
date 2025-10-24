## Accless Experiments

This document covers the different experiments in Accless, and how to reproduce
them.

Table of contents:
- [Hardware set-up](#hardware-set-up)
    - [Faasm baselines](#faasm-baselines)
    - [Knative baselines](#knative-baselines)
    - [Application workflows](#application-workflows)
- [Macro-benchmarks](#macro-benchmarks)

### Hardware Set-Up

You first need to deploy and provision the cluster corresponding to each
baseline.

#### Faasm Baselines

For Faasm-based baselines, we deploy a single IceLake server on Azure, and
deploy Faasm using docker-compose inside. To deploy and provision the server
node, run:

```bash
accli azure sgx-faasm create
accli azure sgx-faasm provision
```

#### Knative Baselines

To-Do

#### Application Workflows

The [applications](../docs/workflows.md) we run as part of our experiments
are written in C++ and support native compilation, for their execution in
Knative, and cross-compilation to WebAssembly, for their execution with Faasm.

To aid with cross-compilation, we provide a docker image to build the different
application workflows with our cross-compilation toolchain. To build the
container image you may run:

```bash
accli docker build -c experiments
```

FIXME: the JWT library has some hard-coded certs, so we need to re-build
the experiments when we have already deployed an APS

To-Do: how to build applications and how to generate the dataset!
CONTINUE HERE!

### Macro-benchmarks

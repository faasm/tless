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
invrs azure sgx-faasm create
invrs azure sgx-faasm provision
```

#### Knative Baselines

To-Do

#### Application Workflows

To-Do: how to build applications and how to generate the dataset!

### Macro-benchmarks

<div align="center">
  <h1><code>Accless</code></h1>

  <p>
    <strong>Access Control for Confidential Serverless</strong>
  </p>

  <p>
  <a href="https://github.com/faasm/tless/actions/workflows/tests.yml">
    <img src="https://github.com/faasm/tless/actions/workflows/tests.yml/badge.svg"
         alt="Integration Tests" />
  </a>
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
installed rust, and activated your virtual environment:

```bash
source ./scripts/workon.sh
```

only then you will have access to `accli`, Accless CLI tool:

```bash
# Print help message
accli --help

# All sub-commands accept the `help` command
accli azure --help
```

## Further reading

* [Baselines](./docs/baselines.md) - baselines where we integrate Accless.
* [Experiments](./experiments/README.md) - reproduce the results in the Accless paper.
* [Workflows](./docs/workflows.md) - different workflow applications we run.

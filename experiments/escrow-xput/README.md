## Escrow Throughput-Latency

This experiment compares the throughput-latency characteristic of secret-key
release operations of different trusted escrow solutions and Accless.

As a workload, we run a synthetic function that ..

### Managed HSM

```bash
accli azure managed-hsm create
accli azure managed-hsm provision
accli experiments escrow-xput run --baseline managed-hsm
accli azure managed-hsm delete
```

### Trustee

```bash
accli azure trustee create
accli azure trustee provision
accli experiments escrow-xput run --baseline trustee
accli azure trustee delete
```

### Accless

```bash
accli azure accless create
accli azure accless provision
```

then run the experiments, which will automatically fetch the results:

```bash
accli experiments escrow-xput run --baseline accless
accli experiments escrow-xput run --baseline accless-maa
```

you may finally delete the resources:

```bash
accli azure accless delete
```

### Plot Results

To plot the resulting file, run:

```bash
accli experiments escrow-xput plot
```

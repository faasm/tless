## End-to-End Workflow Execution Latency

This experiment measures the end-to-end execution latency for each of the
implemented workflows.

### Run the experiment

First, make sure you have [deployed the different baselines](FIXME).

Then, you may run the different baselines:

```bash
invrs eval e2e-latency --baseline knative
invrs eval e2e-latency --baseline cc-knative
```

### Plot the results

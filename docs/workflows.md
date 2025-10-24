## Workflows

As part of Accless experiments, we implement four different serverless
applications with different workflow graphs, all based on related work:
* [FINRA](./workflows/finra/README.md) - Based on the AWS FINRA [case study](https://aws.amazon.com/solutions/case-studies/finra-data-validation/).
* [ML Training](./workflows/ml-training/README.md) - Ported from [Orion](https://www.usenix.org/conference/osdi22/presentation/mahgoub) and [RMMap](https://dl.acm.org/doi/abs/10.1145/3627703.3629568).
* [ML Inference](./workflows/ml-inference/README.md) - Ported from [RMMap](https://dl.acm.org/doi/abs/10.1145/3627703.3629568).
* [Word Count](./workflows/word-count/README.md) - Ported from the MapReduce [example](https://github.com/ddps-lab/serverless-faas-workbench/tree/master/aws/cpu-memory/mapreduce) in the FunctionBench paper.


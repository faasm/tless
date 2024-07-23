## Word Count

Workflow based on the MapReduce [example](https://github.com/ddps-lab/serverless-faas-workbench/tree/master/aws/cpu-memory/mapreduce) part of the FunctionBench paper.

![workflow diagram](./serverless_workflows_word_count.png)

### Stages Explained

1. Splitter:
  - Takes as inputs:
    - `N`, the scale factor of the fan out.
    - The bucket with all the documents
  - Work:
    - Works out how many documents (i.e. keys) each function will process.
    - Chains to `N` mapper functions, passing the corresponding slice of the keys.
2. Mapper:
  - Work:
    - Accumulate a histogram of words in the text. TODO: is this what it does actually?
    - Prune to the top 10?

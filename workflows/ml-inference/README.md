## ML Training

Workflow based on the ML inference presented in [RMMap](https://dl.acm.org/doi/abs/10.1145/3627703.3629568).

![workflow diagram](./serverless_workflows_ml_inference.png)

In this workflow we perform inference over the model trained in the ML training
[workflow](../ml-training/README.md).

> [WARNING!] This workload currently relies on running the ML Training workload
> first, to generate the model weights.

## Run the Workflow (Faasm)

First, uploda the batch of images to perform inference on:

```bash
faasmctl s3.upload-dir \
  --bucket ${BUCKET_NAME} \
  --host-path ${PROJ_DIR}/datasets/ml-inference/images-inference-1k \
  --s3-path ml-inference/images-inference-1k
```

Second, upload the WASM files for each stage in the workflow:

```bash
faasmctl upload.workflow \
  ml-inference \
  faasm.azurecr.io/tless-experiments:$(cat ${PROJ_DIR}/VERSION):/usr/local/faasm/wasm/ml-inference
```

Lastly, you may invoke the driver function to trigger workflow execution
with 16 inference functions.

```bash
faasmctl invoke ml-inference driver --cmdline "ml-inference/model ml-inference/images-inference-1k 16"
```

> [!WARNING]
> To use with Faasm, you must make sure that we have `STDOUT_CAPTURE` disabled.

## Run the Workflow (Knative)

> [!WARNING]
> Unfinished

To run the workflow, you must first upload the wikipedia dump to S3:

```bash
export MINIO_URL=$(kubectl -n tless get services -o jsonpath='{.items[?(@.metadata.name=="minio")].spec.clusterIP}')

# Clean bucket first
invrs s3 clear-bucket --bucket-name ${BUCKET_NAME}

# Upload all data files in the directory
invrs s3 upload-dir \
  --bucket-name ${BUCKET_NAME} \
  --host-path ${PROJ_DIR}/datasets/word-count/few-files/ \
  --s3-path word-count/few-files
```

then you may execute the workflow by running:

```bash
${PROJ_ROOT}/workflows/word-count/knative/curl_cmd.sh
```

## Stages Explained

0. Driver: orchestrates function execution (needed in Faasm, not in Knative)
1. Partition: takes as an input an S3 path two numbers: a parallelism for the
  PCA analysis, and a parallelism for the training (i.e. num of random forests).
  It stores in `partition-output` one file for each PCA instance, with all the
  file keys to consume.
2. PCA: performs PCA of the subset of images assigned by 1, and further
  partitions its data into different training functions.
3. Train: train a random forest on the slice of the data given by 2.
4. Validation: aggregate model data and upload it for the ml-inference workflow

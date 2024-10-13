## ML Training

Workflow based on the ML training presented in [Orion]() and [RMMap]()

![workflow diagram]()

In this workflow we train a random forest model using the MNIST 10k dataset.

## Run the Workflow (Faasm)

First, upload the images:

```bash
# Clean bucket first
faasmctl s3.clear-bucket --bucket ${BUCKET_NAME}

# Upload all data files in the directory
faasmctl s3.upload-dir \
  --bucket ${BUCKET_NAME} \
  --host-path ${PROJ_DIR}/datasets/ml-training/mnist-images-10k
  --s3-path ml-training/mnist-images-10k
```

Second, upload the WASM files for each stage in the workflow:

```bash
faasmctl upload.workflow \
  word-count \
  faasm.azurecr.io/tless-experiments:$(cat ${PROJ_DIR}/VERSION):/usr/local/faasm/wasm/word-count
```

Lastly, you may invoke the driver function to trigger workflow execution:

0x7ff800285ab4
```bash
faasmctl invoke ml-training driver --cmdline "word-count/mnist-images-10k 5 8"
```

> [!WARNING]
> To use with Faasm, you must make sure that we have STDOUT_CAPTURE disabled

## Run the Workflow (Knative)

First, deploy the k8s cluster with bare-metal access to SEV nodes:

```bash
TODO

kubectl apply -f ${PROJ_ROOT}/workflows/k8s_common.yaml
kubectl apply -f ${PROJ_ROOT}/workflows/word-count/knative/workflow.yaml
```

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

### NOTES (delete me):

The `driver` function requires the following env. vars:

```
export S3_BUCKET=tless;
export S3_HOST=localhost;
export S3_PASSWORD=minio123;
export S3_PORT=9000;
export S3_USER=minio;

export TLESS_S3_DIR=word-count/few-files;
```

## Stages Explained

0. Driver: orchestrates function execution (needed in Faasm, not in Knative)
1. Partition: takes as an input an S3 path two numbers: a parallelism for the
  PCA analysis, and a parallelism for the training (i.e. num of random forests).
  It stores in `partition-output` one file for each PCA instance, with all the
  file keys to consume.
2. PCA: takes as an input an S3 path, and as an output writes to S3 a
  serialised map of the appearences of different programming languages in the
  wikipedia dump.
3. Train: once all mapper functions are done, iterates over the results S3
  dir and accumulates all results.
4. Validate:

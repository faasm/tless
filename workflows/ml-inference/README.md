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

First, deploy the workflow to the k8s cluster with bare-metal access to SEV nodes:

```bash
export RUNTIME_CLASS_NAME=kata-qemu-sev
export TLESS_VERSION=$(cat ${PROJ_ROOT}/VERSION)

kubectl apply -f ${PROJ_ROOT}/workflows/k8s_common.yaml
envsubst < ${PROJ_ROOT}/workflows/ml-training/knative/workflow.yaml | kubectl apply -f -
```

Second, upload the required data:

```bash
export MINIO_URL=$(kubectl -n tless get services -o jsonpath='{.items[?(@.metadata.name=="minio")].spec.clusterIP}')

# Clean bucket first
invrs s3 clear-dir --prefix ml-inference

# Upload model data
invrs s3 upload-dir --host-path ${PROJ_ROOT}/datasets/ml-inference/model --s3-path ml-inference/model

# Upload image data to perform inference on
invrs s3 upload-dir --host-path ${PROJ_ROOT}/datasets/ml-inference/images-inference-1k --s3-path ml-inference/images-inference-1k
```

then you may execute the workflow by running:

```bash
${PROJ_ROOT}/workflows/ml-inference/knative/curl_cmd.sh
```

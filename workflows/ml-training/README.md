## ML Training

Workflow based on the ML training presented in [Orion](https://www.usenix.org/conference/osdi22/presentation/mahgoub) and [RMMap](https://dl.acm.org/doi/abs/10.1145/3627703.3629568)>

![workflow diagram](./serverless_workflows_ml_training.png)

In this workflow we train a random forest model using the MNIST 10k dataset.

## Run the Workflow (Faasm)

First, upload the images:

```bash
faasmctl s3.clear-bucket --bucket ${BUCKET_NAME}

# Upload all data files in the directory
faasmctl s3.upload-dir \
  --bucket ${BUCKET_NAME} \
  --host-path ${PROJ_ROOT}/datasets/ml-training/mnist-images-2k \
  --s3-path ml-training/mnist-images-2k
```

Second, upload the WASM files for each stage in the workflow:

```bash
faasmctl upload.workflow \
  ml-training \
  faasm.azurecr.io/tless-experiments:$(cat ${PROJ_DIR}/VERSION):/usr/local/faasm/wasm/ml-training
```

Lastly, you may invoke the driver function to trigger workflow execution
with 2 PCA functions, and 8 random forest trees.

```bash
faasmctl invoke ml-training driver --cmdline "ml-training/mnist-images-2k 2 8"
```

Training the full 10k images inside SGX takes up to (almost) 30'. It can be
done with the following command:

```bash
faasmctl invoke ml-training driver --cmdline "ml-training/mnist-images-10k 4 8"
```

## Run the Workflow (Knative)

First, deploy the workflow to the k8s cluster with bare-metal access to SEV nodes:

```bash
export RUNTIME_CLASS_NAME=kata-qemu-sev
export TLESS_VERSION=$(cat ${PROJ_ROOT}/VERSION)

kubectl apply -f ${PROJ_ROOT}/workflows/k8s_common.yaml
envsubst < ${PROJ_ROOT}/workflows/ml-training/knative/workflow.yaml | kubectl apply -f -
```

Second, upload the images:

```bash
export MINIO_URL=$(kubectl -n tless get services -o jsonpath='{.items[?(@.metadata.name=="minio")].spec.clusterIP}')

# Clean dir
invrs s3 clear-dir --prefix ml-training

# Upload all data files in the directory
invrs upload-dir --host-path ${PROJ_ROOT}/datasets/ml-training/mnist-images-2k --s3-path ml-training/mnist-images-2k
```

then you may execute the workflow by running:

```bash
${PROJ_ROOT}/workflows/ml-training/knative/curl_cmd.sh
```

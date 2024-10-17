## FINRA Analaysis

Workflow based on the AWS FINRA [case study](
https://aws.amazon.com/solutions/case-studies/finra-data-validation/) and the
workflow implementation from [RMMap](
https://dl.acm.org/doi/abs/10.1145/3627703.3629568).

![FINRA workflow diagram](./serverless_workflows_finra.png)

## Run the Workflow (Faasm)

First, upload the transaction data to analyze. We use a data dump from Yahoo
finance:

```bash
faasmctl s3.upload-file \
  --bucket ${BUCKET_NAME} \
  --host-path ${PROJ_DIR}/datasets/finra/yfinance.csv \
  --s3-path finra/yfinance.csv
```

Second, upload the WASM files for each stage in the workflow:

```bash
faasmctl upload.workflow \
  finra \
  faasm.azurecr.io/tless-experiments:$(cat ${PROJ_DIR}/VERSION):/usr/local/faasm/wasm/finra
```

Lastly, you may invoke the driver function to trigger workflow execution
with 20 inference functions:

```bash
faasmctl invoke finra driver --cmdline "finra/yfinance.csv 20"
```

> [!WARNING]
> The original paper calls for 200 parallel instances but, given the lack of
> scalability of both SGX and SNP, we stick with 20.

## Run the Workflow (Knative)

First, deploy the workflow to the k8s cluster with bare-metal access to SEV nodes:

```bash
export RUNTIME_CLASS_NAME=kata-qemu-sev
export TLESS_VERSION=$(cat ${PROJ_ROOT}/VERSION)

kubectl apply -f ${PROJ_ROOT}/workflows/k8s_common.yaml
envsubst < ${PROJ_ROOT}/workflows/word-count/knative/workflow.yaml | kubectl apply -f -
```

Second, upload the trades data to the MinIO server in K8s:

```bash
export MINIO_URL=$(kubectl -n tless get services -o jsonpath='{.items[?(@.metadata.name=="minio")].spec.clusterIP}')

# Clean bucket first
invrs s3 clear-bucket --bucket-name ${BUCKET_NAME}

# Upload all data files in the directory
invrs s3 upload-key \
  --host-path ${PROJ_DIR}/datasets/finra/yfinance.csv \
  --s3-path finra/yfinance.csv
```

then you may execute the workflow by running:

```bash
${PROJ_ROOT}/workflows/finra/knative/curl_cmd.sh
```

## Fetch the data

To re-build the dataset, you may run, from this directory:

```bash
python3 ./fetch_data.py
```

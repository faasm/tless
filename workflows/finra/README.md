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

> [!WARNING]
> Unfinished

## Fetch the data

To re-build the dataset, you may run, from this directory:

```bash
python3 ./fetch_data.py
```

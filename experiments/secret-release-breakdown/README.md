# Attribute-Minting Latency Breakdown

This experiment breaks down the overhead of each (client-side) operation
involved in the attribute-minting protocol. The results of this experiment are
included in Table 4.

## SNP (Bare Metal)

This part assumes you have access to a host with SNP enabled. In that case,
first set-up the cVM image (if you have not before):

```bash
accli dev cvm setup [--clean]
```

then you may start the attestation service locally:

```bash
accli attestation-service run --certs-dir ./config/attestation-service/certs --force-clean-certs
export AS_CERT_DIR="./config/attestation-service/certs"
```

now you can re-build the application inside the cVM, and run it with:

```bash
accli applications build --clean --as-cert-dir ${AS_CERT_DIR} --in-cvm

AS_URL=$(accli attestation-service health --url "https://0.0.0.0:8443" --cert-dir ${AS_CERT_DIR} 2>&1 \
    | grep "attestation service is healthy and reachable on:" | awk '{print $NF}')
accli applications run function escrow-xput --as-url ${AS_URL} --as-cert-dir ${AS_CERT_DIR} --in-cvm
```

you should see the breakdown results printed to the standard out.

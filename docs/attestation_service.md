# Attestation Service

## Certificates

The attestation service uses a self-signed certificate for HTTPS, which we
need to make available to the Accless library. This certificate also needs to
be mapped to the IP where the attesation-service is running, so we need to
support changing it somewhat easily in our experiments.

TODO: MECHANISM TO REPLACE CERTS

Right now, as a work-around, we manually patch the workloads for every
deployment of the attestation service.

### Accless-Faasm

Inside the SGX VM, first run `ip addr`, and get the IP address of the host.
Then generate the new certificates:

```bash
export AS_URL="10.0.0.4"
cd attestation-service
./bin/gen_keys.sh --force
```

Now you need to patch all the workflows. First, get a CLI container running:

```bash
invrs docker cli
cd ../
```

then re-build the JWT verification library:



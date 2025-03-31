# Scalability of Trusted Escrows

This experiment measures the scalability (as latency vs throughout) of different
state-of-the art trusted escrow designs.

We compare two escrows:
1. Manual deployment of [Trustee](
  https://github.com/confidential-containers/trustee) in a cVM in Azure
2. Fully-managed deployment of a Managed HSM on Azure

In both cases, we measure the latency of a Secret Key Release (SKR): releasing
a key subject to a policy check that demands an attestation token. The attestation
token is granted by different entities in each set-up:
1. Attestation token is granted by Trustee itself, by querying the `attest`
  endpoint with our HW attestation evidence.
2. Attestation token is granted by an instance of an Azure Attestation provider.

In both cases as well, the client measuring the latency (i.e. issuing SKR
requests) is running in an SNP cVM on Azure, so the HW attestation evidence
is based on the cVM's vTPM.

## Trustee

### Deploy

### Run

To run the stress test on Trustee, you first must start the KBS:

```bash
cd /home/tless/git/confidential-containers/trustee/kbs/test
sudo ../../target/release/kbs --config-file ./config/kbs.toml
```

## Managed HSM

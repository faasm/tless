# Scalability of Trusted Escrows

This experiment measures the scalability (as latency vs throughout) of different
state-of-the art trusted escrow designs.

We compare two escrows:
1. Manual deployment of [Trustee](
  https://github.com/confidential-containers/trustee) in a cVM in Azure
2. Fully-managed deployment of a Managed HSM on Azure
with the ABE-based key derivation algorithm in TLess.

We measure the latency of a Secret Key Release (SKR): releasing
a key subject to a policy check that demands an attestation token. The attestation
token is granted by different entities in each set-up:
1. Attestation token is granted by Trustee itself, by querying the `attest`
  endpoint with our HW attestation evidence.
2. Attestation token is granted by an instance of an Azure Attestation provider.

In both cases as well, the client measuring the latency (i.e. issuing SKR
requests) is running in an SNP cVM on Azure, so the HW attestation evidence
is based on the cVM's vTPM.

As a consequence, when running the [Trustee](#trustee) and [Managed HSM](
#managed-hsm) baselines, you will have to SSH into the client cVM.

## Trustee

### Deploy

First, deploy our set-up with two SNP-based cVMs on Azure. One will act as
the client, and the other one as the Trustee server.

```bash
invrs azure trustee create
invrs azure trustee provision
```

### Run

To run the experiments, first SSH into the server machine and start Trustee
(in particular the KBS):

```bash
# Client and Server IP addresses should appear
invrs azure trustee ssh

# Take note of the server's IP address
```

```bash
# tless@tless-trustee-server
cd /home/tless/git/confidential-containers/trustee/kbs/test
sudo ../../target/release/kbs --config-file ./config/kbs.toml
```

then, SSH into the client and:

```bash
cd git/faasm/tless
# TODO: set this env. var as part of provisioning
export TLESS_KBS_URL=https://${server_ip_from_above}:8080
source ./bin/workon.sh
invrs ubench escrow-xput run --baseline trustee
```

### Clean-Up

Once you are done running the experiment, you may copy the results from the
cVM by running:

```bash
invrs azure trustee scp-results
invrs azure trustee delete
```

## Managed HSM

### Deploy

```
invrs azure managed-hsm create
invrs azure managed-hsm provision
```

Then, SSH into the corresponding cVM:

```bash
invrs azure managed-hsm ssh
```

### Run (inside cVM)

To run the experiment, you may run:

```bash
invrs ubench escrow-xput run --baseline managed-hsm
```

then you may exit the cVM.

### Clean-Up

Once you are done running the experiment, you may copy the results from the
cVM by running:

```bash
invrs azure managed-hsm scp-results
invrs azure managed-hsm delete
```

## TLess

## Plot

```
invrs ubench escrow-xput plot
```


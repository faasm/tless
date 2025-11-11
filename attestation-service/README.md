# Attesation Service

This is a reference implementation of an attestation service in Accless.

The attestation service is a special type of attribute-providing service that
acts as a relying party in a remote attestation protocol with worker TEEs in
Accless.

The current implementation supports verifying attestation evidence from Intel
SGX enclaves and SEV-SNP confidential VMs. Intel TDX will come next.

## Quick Start

To start an instance of the attestation service, run:

```bash
accli attestation-service run [--help]
```

which builds and runs an instance of the attestation service.

## Protocol Details

The remote attestation protocol is initiated by worker TEEs. Independently of
the TEE implementation they:
1. Request an attestation report from the root-of-trust in the platform.
2. Initiate a Diffie-Helman key exchange, generating an ephemeral keypair.
3. Include in the attestation report the public halve.
4. `POST` the attestation report to the TEE-specific endpoint in the attestation
   service.
5. The attestation service verifies the report and extracts the public key.
6. The attestation service dervies a shared secret.
7. The attestation generates a CP-ABE key based on a set of attributes in the
   attestation report.
8. The attestation report puts all information in a JWT and encodes it with
   its private key (mapped to a well-known certificate).
9. For secrecy, it wraps the signed JWT in an encrypted payload, using the
   derived shared key.

## A Note On Certificates

# Escrow Throughput-Latency - Accless Baseline

This directory holds the source code for the sample function that we use to
measure the overheads of Accless access control mechanisms.

Secret key-release in Accless works as follows:
0. Application code generates a private/public key pair (needed here?)
1. Application code fetches a HW attestation report including the public key
  as additional data.
2. Application code validates the HW attestation report by sending it to an
  instance of the MAA service, and receiving a signed JWT in response.
3. Inside the JWT, encrypted with our public key, we have a symmetric key.
4. We use the symmetric key to decrypt the attestation chain (in this demo,
  its just a sample payload).
5. Based on the attestation chain, we generate a secret.

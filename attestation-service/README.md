# Attesation Service

This is a very simple implementation of an attestation service that runs in a
TEE. It receives attestation reports, validates them, and returns a shared
secret for all ACFs in Accless.

To-Do:
* Add attestation endpoint to attest the AS
    * Think about how to verify the measurement of the AS (hard-code pub key)
* Add HTTPS

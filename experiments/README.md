# Accless Experiments

Figure 5:
- 5.a: [Escrow Throughput-Latency](./escrow-xput/README.md) - FINISH ME
- 5.a: [Escrow Cost](./escrow-cost/README.md) - FINISH ME
Table 4: [Attribute Minting Latency Breakdown](./secret-release-breakdown/README.md)

List of experiment claims -> Experiment that validates them:
C1. Accless is cheaper than centralized escrow -> E1
C2. Accless has better throughput-latency than centralized escrow -> E1
C3. Accless has better throughput-latency than single-authority CP-ABE -> E1
    FIXME: this is not true. what if we increase the size of the VM running the single-auth system?
C4. The size of the policy does not affect decryption time.
C5. The attribute minting protocol introduces negligible overhead compared to ??
C6. The attribute minting protocol introduces negligible overhead compared to cold-start time.
C7. Accless introduces negligible overhead in the end-to-end execution of workflows.

List of experiments:
E1. Throughput-latency of different access control mechanisms.
E2. Micro-benchmark of decryption time as we increase the number of attestation services. (also include encryption time and the corresponding CP-ABE operations like keygen) (needs I6)
E3. Access control breakdown (time to "decrypt" payload)
E4. Cold-start breakdown

Big implementation tasks:
I1. Verify azure cVM reports -> Done
I2. Actually implement the user-side encryption of data from template graph
I3. Run SGX functions from accli
I4. Embed accless checks in S3 library
I5. Support running with multiple replicated attestation-services -> Done
I6. Implement CP-ABE hybrid scheme.

Order:
- Escrow-xput:
    - Use as opportunity to fix SNP HW mode
    - Use as opportunity to try to run SNP bare-metal stuff from `accli`.
    - Use as an opportunity to fix SNP in a para-virtualized VM
        - If we could get rid of the annoyint azguestattestaion crate that would be perfect, and vendor in the code.
- Breakdown table:
    - Compile to native and cross-compile to WASM
    - Use as opportunity to fix SGX HW mode
    - Use as opportunity to try to run WASM functions through Faasm in the `accli`.
    - SNP breakdown could be run either para-virtualized or bare metal.
- Cold start CDF:
    - Use as opportunity to close the loop in generating template graph and uploading encrypted dta
- Chaining ubench
    - Use as opportunity to close the loop on the chainig protocol w/ CP-ABE
- Workflows
    - Move workflows to `./applications`

#include "abe4.h"
#include "attestation/attestation.h"
#include "jwt.h"

#include <iostream>

int main() {
    std::cout << "att-client-sgx: running test..." << std::endl;

    // Get the ID and MPK we need to encrypt ciphertexts with attributes from
    // this attestation service instance.
    auto [id, partialMpk] = accless::attestation::getAttestationServiceState();
    std::cout << "att-client-sgx: got attesation service's state" << std::endl;
    std::string mpk = accless::abe4::packFullKey({id}, {partialMpk});
    std::cout << "att-client-sgx: packed partial MPK into full MPK"
              << std::endl;

    // These values are hard-coded in the mock SGX library in:
    // `accless/libs/attestation/mock_sgx.cpp`.
    std::string gid = "baz";
    std::string wfId = "foo";
    std::string nodeId = "bar";

    // The labels `wf` and `node` are hard-coded in the attestation-service.
    std::string policy = id + ".wf:" + wfId + " & " + id + ".node:" + nodeId;

    // Generate a test ciphertext that only us, after a succesful attestation,
    // should be able to decrypt.
    auto [gt, ct] = accless::abe4::encrypt(mpk, policy);
    std::cout << "att-client-sgx: ran CP-ABE encryption" << std::endl;

    std::cout << "att-client-sgx: running remote attestation..." << std::endl;
    try {
        const std::string jwt =
            accless::attestation::getMockSgxAttestationJwt();
        if (jwt.empty()) {
            std::cerr << "att-client-sgx: empty JWT returned" << std::endl;
            return 1;
        }

        std::cout << "att-client-sgx: received JWT" << std::endl;
        if (!accless::jwt::verify(jwt)) {
            std::cerr << "att-client-sgx: JWT signature verification failed"
                      << std::endl;
            return 1;
        }
        std::cout << "att-client-sgx: JWT signature verified" << std::endl;

        // Get the partial USK from the JWT, and wrap it in a full key for
        // CP-ABE decryption.
        std::string partialUskB64 =
            accless::jwt::getProperty(jwt, "partial_usk_b64");
        if (partialUskB64.empty()) {
            std::cerr
                << "att-client-sgx: JWT is missing 'partial_usk_b64' field"
                << std::endl;
            return 1;
        }

        std::string uskB64 = accless::abe4::packFullKey({id}, {partialUskB64});

        std::optional<std::string> decrypted_gt =
            accless::abe4::decrypt(uskB64, gid, policy, ct);

        if (!decrypted_gt.has_value()) {
            std::cerr << "att-client-sgx: CP-ABE decryption failed"
                      << std::endl;
            return 1;
        } else if (decrypted_gt.value() != gt) {
            std::cerr << "att-client-sgx: CP-ABE decrypted ciphertexts do not"
                      << " match!" << std::endl;
            return 1;
        }

        std::cout << "att-client-sgx: CP-ABE decryption succesful!"
                  << std::endl;

        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "att-client-sgx: error: " << ex.what() << std::endl;
    } catch (...) {
        std::cerr << "att-client-sgx: unexpected error" << std::endl;
    }

    return 1;
}

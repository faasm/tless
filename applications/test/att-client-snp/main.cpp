#include "accless/abe4/abe4.h"
#include "accless/attestation/attestation.h"
#include "accless/attestation/mock.h"
#include "accless/jwt/jwt.h"

#include <iostream>
#include <stdexcept>
#include <vector>

using namespace accless::attestation::mock;

int main(int argc, char *argv[]) {
    std::cout << "att-client-snp: running test..." << std::endl;

    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.size() != 4) {
        throw std::runtime_error(
            "Expected 2 arguments: --as-url and --as-cert-path");
    }
    std::string asUrl;
    std::string asCertPath;
    for (size_t i = 0; i < args.size(); i += 2) {
        if (args[i] == "--as-url") {
            asUrl = args[i + 1];
        } else if (args[i] == "--as-cert-path") {
            asCertPath = args[i + 1];
        } else {
            throw std::runtime_error("Invalid argument: " + args[i]);
        }
    }

    // Get the ID and MPK we need to encrypt ciphertexts with attributes from
    // this attestation service instance.
    auto [id, partialMpk] =
        accless::attestation::getAttestationServiceState(asUrl, asCertPath);
    std::cout << "att-client-snp: got attesation service's state" << std::endl;
    std::string mpk = accless::abe4::packFullKey({id}, {partialMpk});
    std::cout << "att-client-snp: packed partial MPK into full MPK"
              << std::endl;

    // The labels `wf` and `node` are hard-coded in the attestation-service.
    std::string policy =
        id + ".wf:" + MOCK_WORKFLOW_ID + " & " + id + ".node:" + MOCK_NODE_ID;

    // Generate a test ciphertext that only us, after a succesful attestation,
    // should be able to decrypt.
    std::cout << "att-client-snp: encrypting cp-abe with policy: " << policy
              << std::endl;
    auto [gt, ct] = accless::abe4::encrypt(mpk, policy);
    if (gt.empty() || ct.empty()) {
        std::cerr << "att-client-snp: error running cp-abe encryption"
                  << std::endl;
        return 1;
    }
    std::cout << "att-client-snp: ran CP-ABE encryption" << std::endl;

    std::cout << "att-client-snp: running remote attestation..." << std::endl;
    try {
        const std::string jwt =
            accless::attestation::mock::getMockSnpAttestationJwt(asUrl,
                                                                 asCertPath);
        if (jwt.empty()) {
            std::cerr << "att-client-snp: empty JWT returned" << std::endl;
            return 1;
        }

        std::cout << "att-client-snp: received JWT" << std::endl;
        if (!accless::jwt::verify(jwt)) {
            std::cerr << "att-client-snp: JWT signature verification failed"
                      << std::endl;
            return 1;
        }
        std::cout << "att-client-snp: JWT signature verified" << std::endl;

        // Get the partial USK from the JWT, and wrap it in a full key for
        // CP-ABE decryption.
        std::string partialUskB64 =
            accless::jwt::getProperty(jwt, "partial_usk_b64");
        if (partialUskB64.empty()) {
            std::cerr
                << "att-client-snp: JWT is missing 'partial_usk_b64' field"
                << std::endl;
            return 1;
        }

        std::string uskB64 = accless::abe4::packFullKey({id}, {partialUskB64});

        std::optional<std::string> decrypted_gt =
            accless::abe4::decrypt(uskB64, MOCK_GID, policy, ct);

        if (!decrypted_gt.has_value()) {
            std::cerr << "att-client-snp: CP-ABE decryption failed"
                      << std::endl;
            return 1;
        } else if (decrypted_gt.value() != gt) {
            std::cerr << "att-client-snp: CP-ABE decrypted ciphertexts do not"
                      << " match!" << std::endl;
            std::cerr << "att-client-snp: Original GT: " << gt << std::endl;
            std::cerr << "att-client-snp: Decrypted GT: "
                      << decrypted_gt.value() << std::endl;
            return 1;
        }

        std::cout << "att-client-snp: CP-ABE decryption succesful!"
                  << std::endl;

        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "att-client-snp: error: " << ex.what() << std::endl;
    } catch (...) {
        std::cerr << "att-client-snp: unexpected error" << std::endl;
    }

    return 1;
}

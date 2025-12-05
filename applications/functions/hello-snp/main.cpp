#include "accless/abe4/abe4.h"
#include "accless/attestation/attestation.h"
#include "accless/jwt/jwt.h"

#include <iostream>

/**
 * @brief Performs a single secret-key-release operation using Accless.
 *
 * This function is the main body of Accless secret-key-release operation. It
 * relies on an instance of the attestation-service running, and on being
 * deployed in a genuine SNP cVM. Either in a para-virtualized environment on
 * Azure, or on bare-metal.
 */
int doAcclessSkr() {
    // Get the ID and MPK we need to encrypt ciphertexts with attributes from
    // this attestation service instance.
    auto [id, partialMpk] = accless::attestation::getAttestationServiceState();
    std::cout << "escrow-xput: got attesation service's state" << std::endl;
    std::string mpk = accless::abe4::packFullKey({id}, {partialMpk});
    std::cout << "escrow-xput: packed partial MPK into full MPK" << std::endl;

    std::string gid = "baz";
    std::string wfId = "foo";
    std::string nodeId = "bar";

    // Pick the simplest policy that only relies on the attributes `wf` and
    // `node` which are provided by the attestation-service after a succesful
    // remote attestation.
    std::string policy = id + ".wf:" + wfId + " & " + id + ".node:" + nodeId;

    // Generate a test ciphertext that only us, after a succesful attestation,
    // should be able to decrypt.
    std::cout << "escrow-xput: encrypting cp-abe with policy: " << policy
              << std::endl;
    auto [gt, ct] = accless::abe4::encrypt(mpk, policy);
    if (gt.empty() || ct.empty()) {
        std::cerr << "escrow-xput: error running cp-abe encryption"
                  << std::endl;
        return 1;
    }
    std::cout << "escrow-xput: ran CP-ABE encryption" << std::endl;

    std::cout << "escrow-xput: running remote attestation..." << std::endl;
    try {
        const std::string jwt =
            accless::attestation::snp::getAttestationJwt(gid, wfId, nodeId);
        if (jwt.empty()) {
            std::cerr << "escrow-xput: empty JWT returned" << std::endl;
            return 1;
        }

        if (!accless::jwt::verify(jwt)) {
            std::cerr << "escrow-xput: JWT signature verification failed"
                      << std::endl;
            return 1;
        }

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

        // Run decryption.
        std::optional<std::string> decrypted_gt =
            accless::abe4::decrypt(uskB64, gid, policy, ct);
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

        // End of experiment.
    } catch (const std::exception &ex) {
        std::cerr << "escrow-xput: error: " << ex.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "escrow-xput: unexpected error" << std::endl;
        return 1;
    }

    std::cout << "escrow-xput: experiment succesful" << std::endl;
    return 0;
}

int main(int argc, char **argv) { return doAcclessSkr(); }

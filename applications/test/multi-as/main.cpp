#include "accless/abe4/abe4.h"
#include "accless/attestation/attestation.h"
#include "accless/attestation/mock.h"
#include "accless/jwt/jwt.h"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace accless::attestation::mock;

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

int main(int argc, char *argv[]) {
    std::cout << "multi-as: running test..." << std::endl;

    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.size() != 4) {
        throw std::runtime_error(
            "Expected 2 arguments: --as-urls and --as-cert-paths");
    }
    std::vector<std::string> asUrls;
    std::vector<std::string> asCertPaths;
    for (size_t i = 0; i < args.size(); i += 2) {
        if (args[i] == "--as-urls") {
            asUrls = split(args[i + 1], ',');
        } else if (args[i] == "--as-cert-paths") {
            asCertPaths = split(args[i + 1], ',');
        } else {
            throw std::runtime_error("Invalid argument: " + args[i]);
        }
    }

    if (asUrls.size() != asCertPaths.size()) {
        throw std::runtime_error(
            "Number of URLs and certificate paths must be the same");
    }

    std::vector<std::string> ids;
    std::vector<std::string> partialMpks;
    for (size_t i = 0; i < asUrls.size(); ++i) {
        auto [id, partialMpk] =
            accless::attestation::getAttestationServiceState(asUrls[i],
                                                             asCertPaths[i]);
        ids.push_back(id);
        partialMpks.push_back(partialMpk);
    }
    std::cout << "multi-as: got attesation services' state" << std::endl;

    std::string mpk = accless::abe4::packFullKey(ids, partialMpks);
    std::cout << "multi-as: packed partial MPKs into full MPK" << std::endl;

    std::string policy;
    for (size_t i = 0; i < ids.size(); ++i) {
        policy += ids[i] + ".wf:" + MOCK_WORKFLOW_ID + " & " + ids[i] +
                  ".node:" + MOCK_NODE_ID;
        if (i < ids.size() - 1) {
            policy += " & ";
        }
    }

    std::cout << "multi-as: encrypting cp-abe with policy: " << policy
              << std::endl;
    auto [gt, ct] = accless::abe4::encrypt(mpk, policy);
    if (gt.empty() || ct.empty()) {
        std::cerr << "multi-as: error running cp-abe encryption" << std::endl;
        return 1;
    }
    std::cout << "multi-as: ran CP-ABE encryption" << std::endl;

    std::cout << "multi-as: running remote attestation..." << std::endl;
    try {
        std::vector<std::string> partialUsksB64;
        for (size_t i = 0; i < asUrls.size(); ++i) {
            const std::string jwt =
                accless::attestation::mock::getMockSnpAttestationJwt(
                    asUrls[i], asCertPaths[i]);
            if (jwt.empty()) {
                std::cerr << "multi-as: empty JWT returned" << std::endl;
                return 1;
            }

            std::cout << "multi-as: received JWT from " << asUrls[i]
                      << std::endl;
            if (!accless::jwt::verify(jwt)) {
                std::cerr << "multi-as: JWT signature verification failed for "
                          << asUrls[i] << std::endl;
                return 1;
            }
            std::cout << "multi-as: JWT signature verified for " << asUrls[i]
                      << std::endl;

            std::string partialUskB64 =
                accless::jwt::getProperty(jwt, "partial_usk_b64");
            if (partialUskB64.empty()) {
                std::cerr << "multi-as: JWT is missing 'partial_usk_b64' field"
                          << std::endl;
                return 1;
            }
            partialUsksB64.push_back(partialUskB64);
        }

        std::string uskB64 = accless::abe4::packFullKey(ids, partialUsksB64);

        std::optional<std::string> decrypted_gt =
            accless::abe4::decrypt(uskB64, MOCK_GID, policy, ct);

        if (!decrypted_gt.has_value()) {
            std::cerr << "multi-as: CP-ABE decryption failed" << std::endl;
            return 1;
        } else if (decrypted_gt.value() != gt) {
            std::cerr << "multi-as: CP-ABE decrypted ciphertexts do not"
                      << " match!" << std::endl;
            std::cerr << "multi-as: Original GT: " << gt << std::endl;
            std::cerr << "multi-as: Decrypted GT: " << decrypted_gt.value()
                      << std::endl;
            return 1;
        }

        std::cout << "multi-as: CP-ABE decryption succesful!" << std::endl;

        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "multi-as: error: " << ex.what() << std::endl;
    } catch (...) {
        std::cerr << "multi-as: unexpected error" << std::endl;
    }

    return 1;
}

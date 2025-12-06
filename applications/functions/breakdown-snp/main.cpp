#include "accless/abe4/abe4.h"
#include "accless/attestation/attestation.h"
#include "accless/attestation/ec_keypair.h"
#include "accless/base64/base64.h"
#include "accless/jwt/jwt.h"
#include "utils/time_breakdown.h"

#include <chrono>
#include <fstream>
#include <iostream>

int main(int argc, char **argv) {
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

    // =======================================================================
    // CP-ABE Preparation
    // =======================================================================

    // Get the ID and MPK we need to encrypt ciphertexts with attributes from
    // this attestation service instance.
    auto [id, partialMpk] =
        accless::attestation::getAttestationServiceState(asUrl, asCertPath);
    std::string mpk = accless::abe4::packFullKey({id}, {partialMpk});

    std::string gid = "baz";
    std::string wfId = "foo";
    std::string nodeId = "bar";

    // Pick the simplest policy that only relies on the attributes `wf` and
    // `node` which are provided by the attestation-service after a succesful
    // remote attestation.
    std::string policy = id + ".wf:" + wfId + " & " + id + ".node:" + nodeId;

    // Generate a test ciphertext that only us, after a succesful attestation,
    // should be able to decrypt.
    auto [gt, ct] = accless::abe4::encrypt(mpk, policy);
    if (gt.empty() || ct.empty()) {
        std::cerr << "run_requests(): error running cp-abe encryption"
                  << std::endl;
        throw std::runtime_error(
            "run_requests(): error running cp-abe encryption");
    }

    // =======================================================================
    // Run breakdown
    // =======================================================================

    utils::TimeBreakdown tb{"Accless - Attribute Minting Protocol (SNP)"};
    auto start = std::chrono::steady_clock::now();

    // Generate ephemeral EC keypair.
    accless::attestation::ec::EcKeyPair keyPair;
    tb.checkpoint("generate keypair");

    // Get SNP report
    std::array<uint8_t, 64> reportData = keyPair.getReportData();
    std::vector<uint8_t> reportDataVec(reportData.begin(), reportData.end());
    auto report = accless::attestation::snp::getReport(reportData);
    tb.checkpoint("fetch att. report");

    std::string reportB64 = accless::base64::encodeUrlSafe(report);
    std::string runtimeDataB64 = accless::base64::encodeUrlSafe(reportDataVec);
    std::string body = accless::attestation::utils::buildRequestBody(
        reportB64, runtimeDataB64, gid, wfId, nodeId);

    // Send the request to Accless' attestation service, and get the response
    // back.
    auto response = accless::attestation::getJwtFromReport(
        asUrl, asCertPath, "/verify-snp-report", body);
    tb.checkpoint("send report to AS");

    // Accless' authorization is equivalent to checking if we can decrypt
    // the originaly ciphertext from the AS' response.
    std::string encryptedB64 =
        accless::attestation::utils::extractJsonStringField(response,
                                                            "encrypted_token");
    std::string serverKeyB64 =
        accless::attestation::utils::extractJsonStringField(response,
                                                            "server_pubkey");
    std::vector<uint8_t> encrypted =
        accless::base64::decodeUrlSafe(encryptedB64);
    std::vector<uint8_t> serverPubKey =
        accless::base64::decodeUrlSafe(serverKeyB64);

    // Derive shared secret necessary to decrypt JWT.
    std::vector<uint8_t> sharedSecret =
        keyPair.deriveSharedSecret(serverPubKey);
    if (sharedSecret.size() < accless::attestation::AES_128_KEY_SIZE) {
        throw std::runtime_error("accless(att): derived secret too small");
    }
    std::vector<uint8_t> aesKey(sharedSecret.begin(),
                                sharedSecret.begin() +
                                    accless::attestation::AES_128_KEY_SIZE);
    tb.checkpoint("derive shared secret");

    // Decrypt JWT.
    auto jwt = accless::attestation::decryptJwt(encrypted, aesKey);
    if (jwt.empty()) {
        std::cerr << "escrow-xput: empty JWT returned" << std::endl;
        throw std::runtime_error("escrow-xput: empty JWT returned");
    }
    tb.checkpoint("decrypt JWT response");

    // Verify JWT.
    if (!accless::jwt::verify(jwt)) {
        std::cerr << "escrow-xput: JWT signature verification failed"
                  << std::endl;
        throw std::runtime_error(
            "escrow-xput: JWT signature verification failed");
    }
    tb.checkpoint("verify JWT");

    // Get the partial USK from the JWT, and wrap it in a full key for
    // CP-ABE decryption.
    std::string partialUskB64 =
        accless::jwt::getProperty(jwt, "partial_usk_b64");
    if (partialUskB64.empty()) {
        std::cerr << "att-client-snp: JWT is missing 'partial_usk_b64' field"
                  << std::endl;
        throw std::runtime_error("escrow-xput: bad JWT");
    }
    std::string uskB64 = accless::abe4::packFullKey({id}, {partialUskB64});

    // Run decryption.
    std::optional<std::string> decrypted_gt =
        accless::abe4::decrypt(uskB64, gid, policy, ct);
    if (!decrypted_gt.has_value()) {
        std::cerr << "att-client-snp: CP-ABE decryption failed" << std::endl;
        throw std::runtime_error("escrow-xput: CP-ABE decryption failed");
    } else if (decrypted_gt.value() != gt) {
        std::cerr << "att-client-snp: CP-ABE decrypted ciphertexts do not"
                  << " match!" << std::endl;
        std::cerr << "att-client-snp: Original GT: " << gt << std::endl;
        std::cerr << "att-client-snp: Decrypted GT: " << decrypted_gt.value()
                  << std::endl;
        throw std::runtime_error("escrow-xput: CP-ABE decryption failed");
    }
    tb.checkpoint("cp-abe decrypt");

    return 0;
}

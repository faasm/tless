#include "attestation.h"
#include "base64.h"
#include "ec_keypair.h"
#include "mock.h"
#include <stdexcept>

namespace accless::attestation::mock {

const std::array<uint8_t, 8> MOCK_QUOTE_MAGIC_SGX = {'A', 'C', 'C', 'L',
                                                     'S', 'G', 'X', '!'};

std::string getMockSgxAttestationJwt() {
    // Generate ephemeral EC keypair.
    accless::attestation::ec::EcKeyPair keyPair;

    // Embed EC keypair in empty (mocked) SGX quote.
    auto reportData = keyPair.getReportData();
    std::vector<uint8_t> reportVec(reportData.begin(), reportData.end());

    // Populate the mocked quote.
    auto mockQuote = buildMockQuote(reportVec, MOCK_QUOTE_MAGIC_SGX);

    // Prepare request body from quote.
    std::string quoteB64 = accless::base64::encodeUrlSafe(mockQuote);
    std::string runtimeB64 = accless::base64::encodeUrlSafe(reportVec);
    std::string body = utils::buildRequestBody(quoteB64, runtimeB64, MOCK_GID,
                                               MOCK_WORKFLOW_ID, MOCK_NODE_ID);

    std::string response =
        accless::attestation::getJwtFromReport("/verify-sgx-report", body);
    std::string encryptedB64 =
        accless::attestation::utils::extractJsonStringField(response,
                                                            "encrypted_token");
    std::string serverKeyB64 =
        accless::attestation::utils::extractJsonStringField(response,
                                                            "server_pubkey");

    // Decode response values.
    std::vector<uint8_t> encrypted =
        accless::base64::decodeUrlSafe(encryptedB64);
    std::vector<uint8_t> serverPubKey =
        accless::base64::decodeUrlSafe(serverKeyB64);

    // Derive shared secret necessary to decrypt JWT.
    std::vector<uint8_t> sharedSecret =
        keyPair.deriveSharedSecret(serverPubKey);
    if (sharedSecret.size() < AES_128_KEY_SIZE) {
        throw std::runtime_error("accless(att): derived secret too small");
    }
    std::vector<uint8_t> aesKey(sharedSecret.begin(),
                                sharedSecret.begin() + AES_128_KEY_SIZE);

    // Decrypt JWT.
    return accless::attestation::decryptJwt(encrypted, aesKey);
}
} // namespace accless::attestation::mock

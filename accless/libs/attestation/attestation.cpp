#include "attestation.h"

#include <curl/curl.h>
#include <openssl/evp.h>

#include <iostream>
#include <optional>
#include <stdexcept>
#include <string.h>
#include <vector>

namespace accless::attestation {
// Helper for GET requests
static std::string http_get(const std::string &url,
                            const std::string &certPath) {
    auto &client = http::getHttpClient(certPath);
    return client.get(url);
}

std::pair<std::string, std::string>
getAttestationServiceState(const std::string &asUrl,
                           const std::string &certPath) {
    std::string url = asUrl + "/state";

    std::string response = http_get(url, certPath);

    std::string id = utils::extractJsonStringField(response, "id");
    std::string mpk = utils::extractJsonStringField(response, "mpk");

    return std::make_pair(id, mpk);
}

// endpoint must be one in `/verify-snp-report` or `/verify-sgx-report`.
// the report here is a JSON-string
std::string getJwtFromReport(const std::string &asUrl,
                             const std::string &certPath,
                             const std::string &endpoint,
                             const std::string &reportJson) {
    std::string url = asUrl + endpoint;
    auto &client = http::getHttpClient(certPath);
    return client.postJson(url, reportJson);
}

std::string decryptJwt(const std::vector<uint8_t> &encrypted,
                       const std::vector<uint8_t> &aesKey) {
    if (encrypted.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE ||
        aesKey.size() != AES_128_KEY_SIZE) {
        throw std::runtime_error("accless(att): invalid encrypted payload");
    }

    const uint8_t *iv = encrypted.data();
    size_t cipherLen = encrypted.size() - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    const uint8_t *cipherText = encrypted.data() + AES_GCM_IV_SIZE;
    const uint8_t *tag = encrypted.data() + AES_GCM_IV_SIZE + cipherLen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("accless(att): EVP context allocation failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) !=
            1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE,
                            nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, aesKey.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("accless(att): failed to initialise AES-GCM");
    }

    std::vector<uint8_t> plainText(cipherLen);
    int outLen = 0;
    if (cipherLen > 0 &&
        EVP_DecryptUpdate(ctx, plainText.data(), &outLen, cipherText,
                          static_cast<int>(cipherLen)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("accless(att): AES-GCM decrypt failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                            const_cast<uint8_t *>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("accless(att): failed to set GCM tag");
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, plainText.data() + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("accless(att): AES-GCM authentication failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    size_t plainSize = static_cast<size_t>(outLen + finalLen);
    plainText.resize(plainSize);
    return std::string(plainText.begin(), plainText.end());
}
} // namespace accless::attestation

#include "attestation.h"
#include "base64.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

namespace accless::attestation {

std::string getAttestationServiceUrl() {
    const char *url = std::getenv("ACCLESS_AS_URL");
    if (url == nullptr) {
        throw std::runtime_error("ACCLESS_AS_URL environment variable not set");
    }
    return std::string(url);
}

std::string getAttestationServiceCertPath() {
    const char *path = std::getenv("ACCLESS_AS_CERT_PATH");
    if (path == nullptr) {
        throw std::runtime_error(
            "ACCLESS_AS_CERT_PATH environment variable not set");
    }
    return std::string(path);
}

constexpr size_t SGX_COORD_SIZE = 32;
constexpr size_t SGX_REPORT_DATA_SIZE = 64;
constexpr size_t MOCK_QUOTE_HEADER_SIZE = 16;
constexpr uint32_t MOCK_QUOTE_VERSION = 1;
constexpr size_t AES_128_KEY_SIZE = 16;
constexpr size_t AES_GCM_IV_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;
const std::array<uint8_t, 8> MOCK_QUOTE_MAGIC = {'A', 'C', 'C', 'L',
                                                 'S', 'G', 'X', '!'};

class EcKeyPair {
  public:
    EcKeyPair() : key_(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) {
        if (key_ == nullptr || EC_KEY_generate_key(key_) != 1) {
            if (key_ != nullptr) {
                EC_KEY_free(key_);
            }
            throw std::runtime_error("accless(att): error generating EC key");
        }
    }

    ~EcKeyPair() {
        if (key_ != nullptr) {
            EC_KEY_free(key_);
        }
    }

    EcKeyPair(const EcKeyPair &) = delete;
    EcKeyPair &operator=(const EcKeyPair &) = delete;

    EC_KEY *get() const { return key_; }

    std::array<uint8_t, SGX_REPORT_DATA_SIZE> reportData() const {
        const EC_POINT *point = EC_KEY_get0_public_key(key_);
        const EC_GROUP *group = EC_KEY_get0_group(key_);
        if (point == nullptr || group == nullptr) {
            throw std::runtime_error("accless(att): missing EC public key");
        }

        BN_CTX *ctx = BN_CTX_new();
        if (ctx == nullptr) {
            throw std::runtime_error("accless(att): BN_CTX allocation failed");
        }
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        if (x == nullptr || y == nullptr) {
            BN_CTX_free(ctx);
            BN_free(x);
            BN_free(y);
            throw std::runtime_error("accless(att): BN allocation failed");
        }
        if (EC_POINT_get_affine_coordinates(group, point, x, y, ctx) != 1) {
            BN_CTX_free(ctx);
            BN_free(x);
            BN_free(y);
            throw std::runtime_error(
                "accless(att): failed to read EC public coordinates");
        }

        std::array<uint8_t, SGX_COORD_SIZE> gx_be{};
        std::array<uint8_t, SGX_COORD_SIZE> gy_be{};
        if (BN_bn2binpad(x, gx_be.data(), gx_be.size()) !=
                static_cast<int>(gx_be.size()) ||
            BN_bn2binpad(y, gy_be.data(), gy_be.size()) !=
                static_cast<int>(gy_be.size())) {
            BN_CTX_free(ctx);
            BN_free(x);
            BN_free(y);
            throw std::runtime_error(
                "accless(att): failed serialising EC coordinates");
        }

        std::array<uint8_t, SGX_REPORT_DATA_SIZE> report{};
        for (size_t i = 0; i < SGX_COORD_SIZE; i++) {
            report[i] = gx_be[SGX_COORD_SIZE - 1 - i];
            report[SGX_COORD_SIZE + i] = gy_be[SGX_COORD_SIZE - 1 - i];
        }

        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);

        return report;
    }

  private:
    EC_KEY *key_;
};

std::vector<uint8_t>
buildMockQuote(const std::array<uint8_t, SGX_REPORT_DATA_SIZE> &reportData) {
    std::vector<uint8_t> quote;
    quote.reserve(MOCK_QUOTE_HEADER_SIZE + reportData.size());

    // Magic
    quote.insert(quote.end(), MOCK_QUOTE_MAGIC.begin(), MOCK_QUOTE_MAGIC.end());

    // Version (little-endian)
    uint32_t version = MOCK_QUOTE_VERSION;
    quote.push_back(static_cast<uint8_t>(version));
    quote.push_back(static_cast<uint8_t>(version >> 8));
    quote.push_back(static_cast<uint8_t>(version >> 16));
    quote.push_back(static_cast<uint8_t>(version >> 24));

    // Reserved (little-endian)
    uint32_t reserved = 0;
    quote.push_back(static_cast<uint8_t>(reserved));
    quote.push_back(static_cast<uint8_t>(reserved >> 8));
    quote.push_back(static_cast<uint8_t>(reserved >> 16));
    quote.push_back(static_cast<uint8_t>(reserved >> 24));

    // Report data
    quote.insert(quote.end(), reportData.begin(), reportData.end());

    return quote;
}

std::string base64UrlEncode(const std::vector<uint8_t> &data) {
    std::string encoded = accless::base64::encode(data);
    for (char &c : encoded) {
        if (c == '+') {
            c = '-';
        } else if (c == '/') {
            c = '_';
        }
    }
    return encoded;
}

std::string buildRequestBody(const std::string &quoteB64,
                             const std::string &runtimeB64) {
    std::string body =
        R"({"draftPolicyForAttestation":"","nodeData":{"gid":"baz","workflowId":"foo","nodeId":"bar"},"initTimeData":{"data":"","dataType":""},"quote":")";
    body += quoteB64;
    body += R"(","runtimeData":{"data":")";
    body += runtimeB64;
    body += R"(","dataType":"Binary"}})";
    return body;
}

std::string extractJsonStringField(const std::string &json,
                                   const std::string &field) {
    const std::string key = "\"" + field + "\"";
    const size_t keyPos = json.find(key);
    if (keyPos == std::string::npos) {
        throw std::runtime_error("accless(att): missing JSON field " + field);
    }

    size_t colonPos = json.find(':', keyPos + key.size());
    if (colonPos == std::string::npos) {
        throw std::runtime_error("accless(att): malformed JSON near " + field);
    }

    size_t begin = colonPos + 1;
    while (begin < json.size() &&
           std::isspace(static_cast<unsigned char>(json[begin]))) {
        begin++;
    }
    if (begin >= json.size() || json[begin] != '"') {
        throw std::runtime_error("accless(att): expected string for " + field);
    }

    size_t end = json.find('"', begin + 1);
    while (end != std::string::npos && json[end - 1] == '\\') {
        end = json.find('"', end + 1);
    }
    if (end == std::string::npos) {
        throw std::runtime_error("accless(att): unterminated string in JSON");
    }

    return json.substr(begin + 1, end - begin - 1);
}

std::vector<uint8_t>
deriveSharedSecret(const EcKeyPair &keyPair,
                   const std::vector<uint8_t> &serverPubKey) {
    if (serverPubKey.size() != SGX_REPORT_DATA_SIZE) {
        throw std::runtime_error("accless(att): invalid server pub key size");
    }

    const EC_GROUP *group = EC_KEY_get0_group(keyPair.get());
    if (group == nullptr) {
        throw std::runtime_error("accless(att): EC group missing");
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT *point = EC_POINT_new(group);
    if (ctx == nullptr || x == nullptr || y == nullptr || point == nullptr) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        EC_POINT_free(point);
        throw std::runtime_error("accless(att): failed allocating EC helpers");
    }

    std::array<uint8_t, SGX_COORD_SIZE> gx_be{};
    std::array<uint8_t, SGX_COORD_SIZE> gy_be{};
    for (size_t i = 0; i < SGX_COORD_SIZE; i++) {
        gx_be[i] = serverPubKey[SGX_COORD_SIZE - 1 - i];
        gy_be[i] = serverPubKey[(2 * SGX_COORD_SIZE) - 1 - i];
    }

    if (BN_bin2bn(gx_be.data(), gx_be.size(), x) == nullptr ||
        BN_bin2bn(gy_be.data(), gy_be.size(), y) == nullptr ||
        EC_POINT_set_affine_coordinates(group, point, x, y, ctx) != 1) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        EC_POINT_free(point);
        throw std::runtime_error("accless(att): failed to set peer pub key");
    }

    std::vector<uint8_t> secret(SGX_COORD_SIZE);
    int secretSize = ECDH_compute_key(secret.data(), secret.size(), point,
                                      keyPair.get(), nullptr);

    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);

    if (secretSize <= 0) {
        throw std::runtime_error("accless(att): failed to derive shared key");
    }

    secret.resize(static_cast<size_t>(secretSize));
    return secret;
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

size_t mockCurlWriteCallback(char *ptr, size_t size, size_t nmemb,
                             void *userdata) {
    size_t total = size * nmemb;
    auto *response = static_cast<std::string *>(userdata);
    response->append(ptr, total);
    return total;
}

std::string postMockQuote(const std::string &url, const std::string &certPath,
                          const std::string &body) {
    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error("accless(att): failed to init curl");
    }

    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    std::string response;
    std::string endpoint = url + "/verify-sgx-report";
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, certPath.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mockCurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        size_t len = strlen(errbuf);
        fprintf(stderr, "accless(att): curl error: ");
        if (len) {
            fprintf(stderr, "%s%s", errbuf,
                    ((errbuf[len - 1] != '\n') ? "\n" : ""));
        } else {
            fprintf(stderr, "%s\n", curl_easy_strerror(res));
        }
        throw std::runtime_error("accless(att): curl error posting mock quote");
    }
    if (status != 200) {
        throw std::runtime_error(
            "accless(att): attestation service rejected mock quote");
    }

    return response;
}

std::string getMockSgxAttestationJwt() {
    std::string asUrl = getAttestationServiceUrl();
    std::string certPath = getAttestationServiceCertPath();

    EcKeyPair keyPair;
    auto reportData = keyPair.reportData();
    auto mockQuote = buildMockQuote(reportData);
    std::vector<uint8_t> reportVec(reportData.begin(), reportData.end());

    std::string quoteB64 = base64UrlEncode(mockQuote);
    std::string runtimeB64 = base64UrlEncode(reportVec);
    std::string body = buildRequestBody(quoteB64, runtimeB64);

    std::string response = postMockQuote(asUrl, certPath, body);
    std::string encryptedB64 =
        extractJsonStringField(response, "encrypted_token");
    std::string serverKeyB64 =
        extractJsonStringField(response, "server_pubkey");

    std::vector<uint8_t> encrypted = accless::base64::decode(encryptedB64);
    std::vector<uint8_t> serverPubKey = accless::base64::decode(serverKeyB64);

    std::vector<uint8_t> sharedSecret =
        deriveSharedSecret(keyPair, serverPubKey);
    if (sharedSecret.size() < AES_128_KEY_SIZE) {
        throw std::runtime_error("accless(att): derived secret too small");
    }
    std::vector<uint8_t> aesKey(sharedSecret.begin(),
                                sharedSecret.begin() + AES_128_KEY_SIZE);

    return decryptJwt(encrypted, aesKey);
}
} // namespace accless::attestation

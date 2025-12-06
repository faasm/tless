#include "attestation.h"

#include <curl/curl.h>
#include <openssl/evp.h>

#include <iostream>
#include <optional>
#include <stdexcept>
#include <string.h>
#include <vector>

namespace accless::attestation {
// Must match the signature libcurl expects
static size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb,
                                void *userdata) {
    auto *out = static_cast<std::string *>(userdata);
    if (!out) {
        return 0; // tells libcurl this is an error
    }

    const size_t total = size * nmemb;
    out->append(ptr, total);
    return total;
}

// Helper for GET requests
static std::string http_get(const std::string &url,
                            const std::string &certPath) {
    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error("accless(att): failed to init curl");
    }

    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, certPath.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    CURLcode res = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        size_t len = strlen(errbuf);
        fprintf(stderr, "accless(att): curl error: ");
        if (len) {
            fprintf(stderr, "%s%s", errbuf,
                    ((errbuf[len - 1] != '\n') ? "\n" : ""));
        } else {
            fprintf(stderr, "%s\n", curl_easy_strerror(res));
        }
        throw std::runtime_error("accless(att): curl GET error");
    }
    if (status != 200) {
        throw std::runtime_error(
            "accless(att): GET request failed with status " +
            std::to_string(status));
    }

    return response;
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
    std::string jwt;

    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "accless: failed to initialize CURL" << std::endl;
        throw std::runtime_error("curl error");
    }

    std::string url = asUrl + endpoint;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, certPath.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, reportJson.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(reportJson.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &jwt);

    // TODO: set error-buffer in C++ format

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "accless: CURL error: " << curl_easy_strerror(res)
                  << std::endl;
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        throw std::runtime_error("curl error");
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return jwt;
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

#include "vcek_cache.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>

namespace accless::attestation::snp {
namespace {

constexpr const char *THIM_URL =
    "http://169.254.169.254/metadata/THIM/amd/certification";
constexpr const char *THIM_METADATA_HEADER = "Metadata:true";

struct VcekCache {
    std::once_flag once;
    std::string vcekCert;
    std::string certChain;
    std::string bundle;
    std::string error;
};

VcekCache g_cache;

size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *out = static_cast<std::string *>(userdata);
    if (!out) return 0;
    const size_t total = size * nmemb;
    out->append(ptr, total);
    return total;
}

// Perform one-time VCEK fetch, but *never throw*. If unavailable, returns empty PEM strings.
void initVcekCache() {
    CURL *curl = curl_easy_init();
    if (!curl) {
        g_cache.error = "failed to init curl for VCEK fetch";
        return;
    }

    std::string response;
    char errbuf[CURL_ERROR_SIZE] = {0};

    curl_easy_setopt(curl, CURLOPT_URL, THIM_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 500L);      // do not block
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 300L);

    // Add Metadata:true header
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, THIM_METADATA_HEADER);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, nullptr);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    // IMDS unreachable → not a CVM → silently return empty values
    if (res != CURLE_OK) {
        g_cache.error = std::string("VCEK fetch failed: curl error: ") +
                        (errbuf[0] ? errbuf : curl_easy_strerror(res));
        return;
    }

    if (status != 200) {
        g_cache.error =
            "VCEK fetch failed: HTTP status " + std::to_string(status);
        return;
    }

    // Parse JSON.
    try {
        auto json = nlohmann::json::parse(response);

        g_cache.vcekCert = json.value("vcekCert", "");
        g_cache.certChain = json.value("certificateChain", "");

        // Normalize newlines
        if (!g_cache.vcekCert.empty() && g_cache.vcekCert.back() != '\n')
            g_cache.vcekCert.push_back('\n');

        if (!g_cache.certChain.empty() && g_cache.certChain.back() != '\n')
            g_cache.certChain.push_back('\n');

        g_cache.bundle = g_cache.vcekCert + g_cache.certChain;
    } catch (const std::exception &e) {
        g_cache.error = std::string("VCEK fetch JSON parse error: ") + e.what();
        // Leave empty certs
        return;
    }
}

void ensureInitialized() {
    std::call_once(g_cache.once, initVcekCache);
}

} // namespace

// --- Public API ---

const std::string &getVcekPemBundle() {
    ensureInitialized();
    return g_cache.bundle;
}

const std::string &getVcekCertPem() {
    ensureInitialized();
    return g_cache.vcekCert;
}

const std::string &getVcekChainPem() {
    ensureInitialized();
    return g_cache.certChain;
}
} // namespace accless::attestation::snp

#include "mock.h"
#include "base64.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <memory>
#include <stdexcept>

namespace accless::attestation::mock {
std::vector<uint8_t> buildMockQuote(const std::vector<uint8_t> &reportData,
                                    const std::array<uint8_t, 8> &magic) {
    std::vector<uint8_t> quote;
    quote.reserve(MOCK_QUOTE_HEADER_SIZE + reportData.size());

    quote.insert(quote.end(), magic.begin(), magic.end());

    uint32_t version = MOCK_QUOTE_VERSION;
    quote.push_back(static_cast<uint8_t>(version));
    quote.push_back(static_cast<uint8_t>(version >> 8));
    quote.push_back(static_cast<uint8_t>(version >> 16));
    quote.push_back(static_cast<uint8_t>(version >> 24));

    uint32_t reserved = 0;
    quote.push_back(static_cast<uint8_t>(reserved));
    quote.push_back(static_cast<uint8_t>(reserved >> 8));
    quote.push_back(static_cast<uint8_t>(reserved >> 16));
    quote.push_back(static_cast<uint8_t>(reserved >> 24));

    quote.insert(quote.end(), reportData.begin(), reportData.end());

    return quote;
}

/*
size_t mockCurlWriteCallback(char *ptr, size_t size, size_t nmemb,
                             void *userdata) {
    size_t total = size * nmemb;
    auto *response = static_cast<std::string *>(userdata);
    response->append(ptr, total);
    return total;
}

std::string postMockQuote(const std::string &url, const std::string &certPath,
                          const std::string &body,
                          const std::string &endpoint) {
    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error("accless(att): failed to init curl");
    }

    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;

    std::string response;
    std::string fullUrl = url + endpoint;
    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
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
*/
} // namespace accless::attestation

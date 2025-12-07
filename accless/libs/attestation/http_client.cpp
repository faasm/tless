#include "attestation.h"

#include <cstring>
#include <curl/curl.h>
#include <unordered_map>

namespace accless::attestation::http {
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

HttpClient::HttpClient(const std::string &certPath) : certPath_(certPath) {
    curl_ = curl_easy_init();
    if (!curl_) {
        throw std::runtime_error("accless(att): failed to init curl");
    }

    // Set options that don’t change between requests
    memset(errbuf_, 0, sizeof(errbuf_));
    curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl_, CURLOPT_CAINFO, certPath_.c_str());
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response_);
    curl_easy_setopt(curl_, CURLOPT_ERRORBUFFER, errbuf_);
}

HttpClient::~HttpClient() {
    if (curl_) {
        curl_easy_cleanup(curl_);
    }
}

std::string HttpClient::get(const std::string &url) {
    prepareRequest();
    curl_easy_setopt(curl_, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

    perform();

    return response_;
}

std::string HttpClient::postJson(const std::string &url,
                                 const std::string &body) {
    prepareRequest();

    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_POST, 1L);
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(body.size()));

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);

    perform();

    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, nullptr);
    curl_slist_free_all(headers);
    return response_;
}

void HttpClient::prepareRequest() {
    response_.clear();
    memset(errbuf_, 0, sizeof(errbuf_));

    // Make sure we’re not leaking POST state into a GET or vice versa
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, nullptr);
    curl_easy_setopt(curl_, CURLOPT_HTTPGET, 0L);
    curl_easy_setopt(curl_, CURLOPT_POST, 0L);
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, nullptr);
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, 0L);

    // WRITEDATA always points to our response_ string
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response_);
}

void HttpClient::perform() {
    CURLcode res = curl_easy_perform(curl_);
    long status = 0;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &status);

    if (res != CURLE_OK) {
        const size_t len = std::strlen(errbuf_);
        std::string msg = "accless(att): curl error: ";
        if (len) {
            msg += errbuf_;
        } else {
            msg += curl_easy_strerror(res);
        }
        throw std::runtime_error(msg);
    }

    if (status != 200) {
        throw std::runtime_error(
            "accless(att): HTTP request failed with status " +
            std::to_string(status));
    }
}

thread_local std::unordered_map<std::string, std::unique_ptr<HttpClient>>
    tlsClients;

HttpClient &getHttpClient(const std::string &certPath) {
    auto it = tlsClients.find(certPath);
    if (it == tlsClients.end()) {
        it =
            tlsClients.emplace(certPath, std::make_unique<HttpClient>(certPath))
                .first;
    }
    return *it->second;
}
} // namespace accless::attestation::http

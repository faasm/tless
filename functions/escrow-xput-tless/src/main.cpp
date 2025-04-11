#include <chrono>
#include <cstdlib>
#include <curl/curl.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <semaphore>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "AttestationClient.h"
#include "AttestationClientImpl.h"
#include "AttestationParameters.h"
#include "HclReportParser.h"
#include "TpmCertOperations.h"

#include "logger.h"
#include "tless_abe.h"
#include "utils.h"

using json = nlohmann::json;

using namespace attest;

std::vector<std::string> split(const std::string &str, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string token;

    while (std::getline(ss, token, delim)) {
        result.push_back(token);
    }

    return result;
}

// Get the URL of our own attestation service (**not** MAA)
std::string getAttestationServiceUrl() {
    const char *val = std::getenv("AS_URL");
    return val ? std::string(val) : "https://127.0.0.1:8443";
}

void tpmRenewAkCert() {
    TpmCertOperations tpmCertOps;
    bool renewalRequired = false;
    auto result = tpmCertOps.IsAkCertRenewalRequired(renewalRequired);
    if (result.code_ != AttestationResult::ErrorCode::SUCCESS) {
        std::cerr << "accless: error checking AkCert renewal state"
                  << std::endl;

        if (result.tpm_error_code_ != 0) {
            std::cerr << "accless: internal TPM error occured: "
                      << result.description_ << std::endl;
            throw std::runtime_error("internal TPM error");
        } else if (result.code_ == attest::AttestationResult::ErrorCode::
                                       ERROR_AK_CERT_PROVISIONING_FAILED) {
            std::cerr << "accless: attestation key cert provisioning delayed"
                      << std::endl;
            throw std::runtime_error("internal TPM error");
        }
    }

    if (renewalRequired) {
        auto replaceResult = tpmCertOps.RenewAndReplaceAkCert();
        if (replaceResult.code_ != AttestationResult::ErrorCode::SUCCESS) {
            std::cerr << "accless: failed to renew AkCert: "
                      << result.description_ << std::endl;
            throw std::runtime_error("accless: internal TPM error");
        }
    }
}

AttestationResult parseClientPayload(
    const unsigned char *clientPayload,
    std::unordered_map<std::string, std::string> &clientPayloadMap) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    assert(clientPayload != nullptr);

    Json::Value root;
    Json::Reader reader;
    std::string clientPayloadStr(
        const_cast<char *>(reinterpret_cast<const char *>(clientPayload)));
    bool success = reader.parse(clientPayloadStr, root);
    if (!success) {
        std::cout << "accless: error parsing the client payload JSON"
                  << std::endl;
        result.code_ =
            AttestationResult::ErrorCode::ERROR_INVALID_INPUT_PARAMETER;
        result.description_ = std::string("Invalid client payload Json");
        return result;
    }

    for (Json::Value::iterator it = root.begin(); it != root.end(); ++it) {
        clientPayloadMap[it.key().asString()] = it->asString();
    }

    return result;
}

/*
 * This method populates all the attestation parameters to send to the MAA,
 * including reading the TPM measurements.
 */
AttestationParameters
getAzureAttestationParameters(AttestationClient *attestationClient) {
    std::string attestationUrl = "https://accless.eus.attest.azure.net";

    // Client parameters
    attest::ClientParameters clientParams = {};
    clientParams.attestation_endpoint_url =
        (unsigned char *)attestationUrl.c_str();
    // TODO: can we add a public key here?
    std::string nonce = "foo";
    std::string clientPayload = "{\"nonce\":\"" + nonce + "\"}";
    clientParams.client_payload = (unsigned char *)clientPayload.c_str();
    clientParams.version = CLIENT_PARAMS_VERSION;

    AttestationParameters params = {};
    std::unordered_map<std::string, std::string> clientPayloadMap;
    if (clientParams.client_payload != nullptr) {
        auto result =
            parseClientPayload(clientParams.client_payload, clientPayloadMap);
        if (result.code_ != AttestationResult::ErrorCode::SUCCESS) {
            std::cout << "accless: error parsing client payload" << std::endl;
            throw std::runtime_error("error parsing client payload");
        }
    }

    auto result = ((AttestationClientImpl *)attestationClient)
                      ->getAttestationParameters(clientPayloadMap, params);
    if (result.code_ != AttestationResult::ErrorCode::SUCCESS) {
        std::cout << "accless: failed to get attestation parameters"
                  << std::endl;
        throw std::runtime_error("failed to get attestation parameters");
    }

    return params;
}

/*
 * This method gets a JWT from the MAA in response of a set of attestation
 * parameters.
 */
std::string maaGetJwtFromParams(AttestationClient *attestationClient,
                                const AttestationParameters &params,
                                const std::string &attestationUri) {
    bool is_cvm = false;
    bool attestation_success = true;
    std::string jwt_str;

    unsigned char *jwt = nullptr;
    auto attResult = ((AttestationClientImpl *)attestationClient)
                         ->Attest(params, attestationUri, &jwt);
    if (attResult.code_ != attest::AttestationResult::ErrorCode::SUCCESS) {
        std::cerr
            << "accless: error getting attestation from attestation client"
            << std::endl;
        Uninitialize();
        throw std::runtime_error(
            "failed to get attestation from attestation client");
    }

    std::string jwtStr = reinterpret_cast<char *>(jwt);
    attestationClient->Free(jwt);

    return jwtStr;
}

size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t totalSize = size * nmemb;
    auto *response = static_cast<std::string *>(userdata);
    response->append(ptr, totalSize);
    return totalSize;
}

/*
 * This methodd gets a JWT from our own attestation service by POST-ing the
 * SNP report.
 */
std::string asGetJwtFromReport(const std::string &asUrl,
                               const std::vector<uint8_t> &snpReport) {
    std::string jwt;

    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "accless: failed to initialize CURL" << std::endl;
        throw std::runtime_error("curl error");
    }

    curl_easy_setopt(curl, CURLOPT_URL, asUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(
        curl, CURLOPT_CAINFO,
        "/home/tless/git/faasm/tless/attestation-service/certs/cert.pem");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, snpReport.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, snpReport.size());

    struct curl_slist *headers = nullptr;
    headers =
        curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Set write function and data
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &jwt);

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

void validateJwtClaims(const std::string &jwtStr, bool verbose = false) {
    // Prase attestation token to extract isolation tee details
    auto tokens = split(jwtStr, '.');
    if (tokens.size() < 3) {
        std::cerr << "accless: error validating jwt: not enough tokens"
                  << std::endl;
        throw std::runtime_error("accless: error validating jwt");
    }

    json attestationClaims = json::parse(base64decode(tokens[1]));
    std::string attestationType;
    std::string complianceStatus;
    try {
        attestationType =
            attestationClaims["x-ms-isolation-tee"]["x-ms-attestation-type"]
                .get<std::string>();
        complianceStatus =
            attestationClaims["x-ms-isolation-tee"]["x-ms-compliance-status"]
                .get<std::string>();
    } catch (...) {
        std::cerr << "accless: jwt does not have the expected claims"
                  << std::endl;
        throw std::runtime_error("accless: error validating jwt");
    }

    if (!((attestationType == "sevsnpvm") &&
          (complianceStatus == "azure-compliant-cvm"))) {
        std::cerr << "accless: jwt validation does not pass" << std::endl;
    }

    if (verbose) {
        std::cout << "accless: jwt validation passed" << std::endl;
    }
}

/*
 * This method gets the HCL report from a vTPM in Azure, and extracts the SNP
 * report out of it.
 */
std::vector<uint8_t> getSnpReportFromTPM() {
    // First, get HCL report
    Tpm tpm;
    Buffer hclReport = tpm.GetHCLReport();

    Buffer snpReport;
    Buffer runtimeData;
    HclReportParser reportParser;

    auto result = reportParser.ExtractSnpReportAndRuntimeDataFromHclReport(
        hclReport, snpReport, runtimeData);
    if (result.code_ != AttestationResult::ErrorCode::SUCCESS) {
        std::cerr << "accless: error parsing snp report from HCL report"
                  << std::endl;
        throw std::runtime_error("error parsing HCL report");
    }

    return snpReport;
}

void decrypt(const std::string &jwtStr, tless::abe::CpAbeContextWrapper &ctx,
             std::vector<uint8_t> &cipherText, bool compare = false) {
    // TODO: in theory, the attributes should be extracted frm the JWT
    std::vector<std::string> attributes = {"foo", "bar"};

    auto actualPlainText = ctx.cpAbeDecrypt(attributes, cipherText);
    if (actualPlainText.empty()) {
        std::cerr << "accless: error decrypting cipher-text" << std::endl;
        throw std::runtime_error("error decrypting secret");
    }

    if (compare) {
        // Compare
        std::string plainText =
            "dance like no one's watching, encrypt like everyone is!";
        std::string actualPlainTextStr;
        actualPlainTextStr.assign(
            reinterpret_cast<char *>(actualPlainText.data()),
            actualPlainText.size());
        if (actualPlainTextStr == plainText) {
            std::cout << "accless: key-release succeeded" << std::endl;
        }
        std::cout << "accless: actual plain-text: " << actualPlainTextStr
                  << std::endl;
    }
}

// TODO: do another benchmark where we query our attestation service instead,
// and compare it with the MAA
std::chrono::duration<double> runRequests(int numRequests, int maxParallelism,
                                          bool maa = false) {
    // ---------------------- Set Up CP-ABE -----------------------------------

    // Initialize CP-ABE ctx and create a sample secret
    auto &ctx = tless::abe::CpAbeContextWrapper::get(
        tless::abe::ContextFetchMode::Create);
    std::string plainText =
        "dance like no one's watching, encrypt like everyone is!";
    std::string policy = "\"foo\" and \"bar\"";
    auto cipherText = ctx.cpAbeEncrypt(policy, plainText);

    // Renew vTPM certificates if needed
    tpmRenewAkCert();

    // ----------------------- Benchmark  -------------------------------------

    std::counting_semaphore semaphore(maxParallelism);
    std::vector<std::thread> threads;
    auto start = std::chrono::steady_clock::now();

    if (maa) {
        // FIXME: the MAA benchmark has some spurious race conditions

        std::string attestationUri = "https://accless.eus.attest.azure.net";

        // Initialize Azure Attestation client
        AttestationClient *attestationClient = nullptr;
        Logger *logHandle = new Logger();
        if (!Initialize(logHandle, &attestationClient)) {
            std::cerr << "accless: failed to create attestation client object"
                      << std::endl;
            Uninitialize();
            throw std::runtime_error(
                "failed to create attestation client object");
        }

        // Fetching the vTPM measurements is not thread-safe, but would happen
        // in each client anyway, so we execute it only once, but still measure
        // the time it takes
        auto attParams = getAzureAttestationParameters(attestationClient);

        // In the loop, to measure scalability, we only send the HW report for
        // validation with the attestation service (be it Azure or our own att.
        // service)
        for (int i = 1; i < numRequests; ++i) {
            semaphore.acquire();
            threads.emplace_back([&semaphore, attestationClient, &attParams,
                                  attestationUri]() {
                // Validate some of the claims in the JWT
                auto jwtStr = maaGetJwtFromParams(attestationClient, attParams,
                                                  attestationUri);

                // TODO: validate JWT signature

                // TODO: somehow get the public key from the JWT
                validateJwtClaims(jwtStr);

                // Release semaphore
                semaphore.release();
            });
        }

        // Do it once from the main thread to store the return value for
        // decryption
        auto jwtStr =
            maaGetJwtFromParams(attestationClient, attParams, attestationUri);

        for (auto &t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        // Similarly, the decrypt stage is compute-bound, so by running many
        // instances in parallel we are saturating the local CPU. This step is
        // fully distributed, so no issue with running it just once
        decrypt(jwtStr, ctx, cipherText);

        Uninitialize();
    } else {
        std::string asUrl = getAttestationServiceUrl();

        // Fetching the vTPM measurements is not thread-safe, but would happen
        // in each client anyway, so we execute it only once, but still measure
        // the time it takes
        auto snpReport = getSnpReportFromTPM();

        // In the loop, to measure scalability, we only send the HW report for
        // validation with the attestation service (be it Azure or our own att.
        // service)
        for (int i = 1; i < numRequests; ++i) {
            semaphore.acquire();
            threads.emplace_back([&semaphore, &asUrl, &snpReport]() {
                // Get a JWT from the attestation service if report valid
                auto jwtStr =
                    asGetJwtFromReport(asUrl + "/verify-snp-report", snpReport);

                // TODO: somehow get the public key from the JWT
                // TODO: validate some claims in the JWT

                // Release semaphore
                semaphore.release();
            });
        }

        // Do it once from the main thread to store the return value for
        // decryption
        auto jwtStr =
            asGetJwtFromReport(asUrl + "/verify-snp-report", snpReport);

        for (auto &t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        // Similarly, the decrypt stage is compute-bound, so by running many
        // instances in parallel we are saturating the local CPU. This step is
        // fully distributed, so no issue with running it just once
        decrypt(jwtStr, ctx, cipherText);
    }

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsedSecs = end - start;
    std::cout << "Elapsed time (" << numRequests << "): " << elapsedSecs.count()
              << " seconds\n";

    return elapsedSecs;
}

void doBenchmark(bool maa = false) {
    // Write elapsed time to CSV
    std::string fileName = maa ? "accless-maa.csv" : "accless.csv";
    std::ofstream csvFile(fileName, std::ios::out);
    csvFile << "NumRequests,TimeElapsed\n";

    // WARNING: this is copied from invrs/src/tasks/ubench.rs and must be
    // kept in sync!
    std::vector<int> numRequests = {1, 10, 50, 100, 200, 400, 600, 800, 1000};
    int numRepeats = maa ? 1 : 3;
    int maxParallelism = 100;
    try {
        for (const auto &i : numRequests) {
            for (int j = 0; j < numRepeats; j++) {
                auto elapsedTimeSecs = runRequests(i, maxParallelism, maa);
                csvFile << i << "," << elapsedTimeSecs.count() << '\n';
            }
        }
    } catch (...) {
        std::cout << "accless: error running benchmark" << std::endl;
    }

    csvFile.close();
}

void runOnce(bool maa = false) {
    // Renew TPM certificates if needed
    tpmRenewAkCert();

    // Initialize CP-ABE ctx
    auto &ctx = tless::abe::CpAbeContextWrapper::get(
        tless::abe::ContextFetchMode::Create);
    std::string plainText =
        "dance like no one's watching, encrypt like everyone is!";
    std::string policy = "\"foo\" and \"bar\"";
    auto cipherText = ctx.cpAbeEncrypt(policy, plainText);

    std::string jwtStr;
    if (maa) {
        // TODO: attest MAA
        std::string attestationUri = "https://accless.eus.attest.azure.net";

        // Initialize Azure Attestation client
        AttestationClient *attestationClient = nullptr;
        Logger *logHandle = new Logger();
        if (!Initialize(logHandle, &attestationClient)) {
            std::cerr << "accless: failed to create attestation client object"
                      << std::endl;
            Uninitialize();
            throw std::runtime_error(
                "failed to create attestation client object");
        }

        auto attParams = getAzureAttestationParameters(attestationClient);
        jwtStr =
            maaGetJwtFromParams(attestationClient, attParams, attestationUri);
        validateJwtClaims(jwtStr);

        Uninitialize();
    } else {
        std::string asUrl = getAttestationServiceUrl();

        // TODO: attest AS

        auto snpReport = getSnpReportFromTPM();
        jwtStr = asGetJwtFromReport(asUrl + "/verify-snp-report", snpReport);
        std::cout << "out: " << jwtStr << std::endl;
    }

    decrypt(jwtStr, ctx, cipherText);
}

int main(int argc, char **argv) {
    bool maa = ((argc == 2) && (std::string(argv[1]) == "--maa"));
    bool once = ((argc == 2) && (std::string(argv[1]) == "--once"));

    if (once) {
        runOnce();
    } else {
        doBenchmark(maa);
    }
}

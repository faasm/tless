/* Helper methods to interact with Microsoft's Azure Attestation Service */

#include "maa.h"

#include "accless/attestation/ec_keypair.h"
#include "accless/base64/base64.h"

#include "AttestationClient.h"
#include "AttestationClientImpl.h"
#include "AttestationParameters.h"
#include "TpmCertOperations.h"

#include <chrono>
#include <iostream>
#include <nlohmann/json.hpp>
#include <semaphore>
#include <stdarg.h>
#include <thread>
#include <vector>

using json = nlohmann::json;
using namespace attest;

void Logger::Log(const char *log_tag, LogLevel level, const char *function,
                 const int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    size_t len = std::vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    std::vector<char> str(len + 1);

    va_start(args, fmt);
    std::vsnprintf(&str[0], len + 1, fmt, args);
    va_end(args);

    // Uncomment for debug logs
    std::cout << std::string(str.begin(), str.end()) << std::endl;
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

AttestationParameters
getAzureAttestationParameters(AttestationClient *attestationClient,
                              const std::string &attestationUrl,
                              const std::string &nonce) {
    // Client parameters
    attest::ClientParameters clientParams = {};
    clientParams.attestation_endpoint_url =
        (unsigned char *)attestationUrl.c_str();
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

    // Note that this call actually fetches the vTPM report.
    auto result = ((AttestationClientImpl *)attestationClient)
                      ->getAttestationParameters(clientPayloadMap, params);
    if (result.code_ != AttestationResult::ErrorCode::SUCCESS) {
        std::cout << "accless: failed to get attestation parameters"
                  << std::endl;
        throw std::runtime_error("failed to get attestation parameters");
    }

    return params;
}

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

/**
 * @brief Measures time to send N requests to Azure's Attestation Service.
 *
 * This function is a simplified version of the main `runRequests` in
 * `./src/main.cpp` that aims to illustrate the benefits of replacing Azure's
 * Attestation Service with our own implementation running inside a cVM.
 *
 * Given that we don't control the code in the MAA, we cannot perform a full
 * SKR operation. This is, we cannot implement the server-side halve of the
 * attribute minting protocol. Still, the throughput-latency characteristic
 * of the MAA is so bad, that it is enough to just measure the time to:
 * - Fetch once the SNP request.
 * - Send N requests to the MAA for attestation.
 *
 * @param numRequests The number of requests to run.
 * @param maxParallelism The number of parallel threads to use.
 * @param maaUrl URL of Azure's attestation service.
 * @return The time elapsed to run the number of requests.
 */
std::chrono::duration<double>
runMaaRequests(int numRequests, int maxParallelism, const std::string &maaUrl) {
    std::cout << "escrow-xput: beginning MAA benchmark. num reqs: "
              << numRequests << std::endl;

    tpmRenewAkCert();

    std::counting_semaphore semaphore(maxParallelism);
    std::vector<std::thread> threads;

    auto start = std::chrono::steady_clock::now();

    // Generate ephemeral EC keypair.
    accless::attestation::ec::EcKeyPair keyPair;
    std::array<uint8_t, 64> reportData = keyPair.getReportData();
    std::vector<uint8_t> reportDataVec(reportData.begin(), reportData.end());
    std::string reportDataB64 = accless::base64::encodeUrlSafe(reportDataVec);

    // Initialize Azure Attestation client
    AttestationClient *attestationClient = nullptr;
    Logger *logHandle = new Logger();
    if (!Initialize(logHandle, &attestationClient)) {
        std::cerr << "accless: failed to create attestation client object"
                  << std::endl;
        Uninitialize();
        throw std::runtime_error("failed to create attestation client object");
    }

    // Fetching the vTPM measurements is not thread-safe, but would happen
    // in each client anyway, so we execute it only once, but still measure
    // the time it takes
    auto attParams =
        getAzureAttestationParameters(attestationClient, maaUrl, reportDataB64);

    for (int i = 0; i < numRequests; ++i) {
        // Limit how many threads we spawn in parallel by acquiring a semaphore.
        semaphore.acquire();

        threads.emplace_back(
            [&semaphore, &attestationClient, &attParams, &maaUrl]() {
                auto jwtStr =
                    maaGetJwtFromParams(attestationClient, attParams, maaUrl);

                // We could validate some claims in the JWT here.

                // And releasing when the thread is done.
                semaphore.release();
            });
    }

    // Wait for all requests to finish. We do this now, and not at the end
    // to emulate the situation where we would have N independent clients.
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Here all CP-ABE decryption would happen.

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsedSecs = end - start;
    std::cout << "Elapsed time (" << numRequests << "): " << elapsedSecs.count()
              << " seconds\n";

    return elapsedSecs;
}

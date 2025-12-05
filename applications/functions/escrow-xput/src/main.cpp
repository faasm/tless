#include "accless/abe4/abe4.h"
#include "accless/attestation/attestation.h"
#include "accless/attestation/ec_keypair.h"
#include "accless/base64/base64.h"
#include "accless/jwt/jwt.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <semaphore>
#include <thread>

/*
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

size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t totalSize = size * nmemb;
    auto *response = static_cast<std::string *>(userdata);
    response->append(ptr, totalSize);
    return totalSize;
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
std::vector<uint8_t> &cipherText, bool compare = false) { // TODO: in theory,
the attributes should be extracted frm the JWT std::vector<std::string>
attributes = {"foo", "bar"};

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

    // TODO: jwtStr is now a JWE, so we must decrypt it

    decrypt(jwtStr, ctx, cipherText);
}
*/

std::string sendSingleAcclessRequest(const std::vector<uint8_t> &report,
                                     const std::vector<uint8_t> &reportData,
                                     const std::string &gid,
                                     const std::string &workflowId,
                                     const std::string &nodeId) {
    std::string reportB64 = accless::base64::encodeUrlSafe(report);
    std::string runtimeDataB64 = accless::base64::encodeUrlSafe(reportData);
    std::string body = accless::attestation::utils::buildRequestBody(
        reportB64, runtimeDataB64, gid, workflowId, nodeId);

    // Send the request to Accless' attestation service, and get the response
    // back.
    return accless::attestation::getJwtFromReport(
        accless::attestation::snp::getAsEndpoint(false), body);
}

/**
 * @brief Measures time to run N secret-release operations.
 *
 * This function measures the time it takes to perform N secret-release
 * operations in Accless. To emulate having N independent clients, without
 * spawning N isolated VMs, we do the operations each client would do in
 * isolation in serial, and then the ones that stress the scalability of the
 * attestation service, in parallel.
 *
 * This means that the time to run N requests is measured as the sum of:
 * - Time to fetch HW attestation report once.
 * - Time to send N requests in parallel to the AS.
 * - Time to perform the CP-ABE decryption once.
 *
 * We follow the same strategy for the other baselines. Otherwise, for example,
 * we would not be able to retrieve the SNP report from a TPM in parallel N
 * times due to a race condition in the TPM code (or would be serialized by the
 * PSP).
 *
 * @param numRequests The number of requests to run.
 * @param maxParallelism The number of parallel threads to use.
 * @return The time elapsed to run the number of requests.
 */
std::chrono::duration<double> runRequests(int numRequests, int maxParallelism,
                                          bool maa) {
    // =======================================================================
    // CP-ABE Preparation
    // =======================================================================

    // Get the ID and MPK we need to encrypt ciphertexts with attributes from
    // this attestation service instance.
    auto [id, partialMpk] = accless::attestation::getAttestationServiceState();
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
    // Run benchmark
    // =======================================================================

    std::cout << "escrow-xput: beginning benchmark. num reqs: " << numRequests
              << std::endl;

    std::counting_semaphore semaphore(maxParallelism);
    std::vector<std::thread> threads;

    auto start = std::chrono::steady_clock::now();

    // Generate ephemeral EC keypair.
    accless::attestation::ec::EcKeyPair keyPair;
    std::array<uint8_t, 64> reportData = keyPair.getReportData();
    std::vector<uint8_t> reportDataVec(reportData.begin(), reportData.end());

    // Fetching the vTPM measurements is not thread-safe, but would happen
    // in each client anyway, so we execute it only once, but still measure
    // the time it takes.
    auto report = accless::attestation::snp::getReport(reportData);

    for (int i = 1; i < numRequests; ++i) {
        // Limit how many threads we spawn in parallel by acquiring a semaphore.
        semaphore.acquire();

        threads.emplace_back(
            [&semaphore, &report, &reportDataVec, &gid, &wfId, &nodeId]() {
                auto response = sendSingleAcclessRequest(report, reportDataVec,
                                                         gid, wfId, nodeId);
                // And releasing when the thread is done.
                semaphore.release();
            });
    }

    // Send one request out of the loop, to easily process the result.
    auto response =
        sendSingleAcclessRequest(report, reportDataVec, gid, wfId, nodeId);

    // Wait for all requests to finish. We do this now, and not at the end
    // to emulate the situation where we would have N independent clients.
    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

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

    // Decrypt JWT.
    auto jwt = accless::attestation::decryptJwt(encrypted, aesKey);
    if (jwt.empty()) {
        std::cerr << "escrow-xput: empty JWT returned" << std::endl;
        throw std::runtime_error("escrow-xput: empty JWT returned");
    }

    // Verify JWT.
    if (!accless::jwt::verify(jwt)) {
        std::cerr << "escrow-xput: JWT signature verification failed"
                  << std::endl;
        throw std::runtime_error(
            "escrow-xput: JWT signature verification failed");
    }

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

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsedSecs = end - start;
    std::cout << "Elapsed time (" << numRequests << "): " << elapsedSecs.count()
              << " seconds\n";

    return elapsedSecs;
}

void doBenchmark(const std::vector<int> &numRequests, int numWarmupRepeats,
                 int numRepeats, bool maa) {
    // Write elapsed time to CSV
    std::string fileName = maa ? "accless-maa.csv" : "accless.csv";
    std::ofstream csvFile(fileName, std::ios::out);
    csvFile << "NumRequests,TimeElapsed\n";

    // WARNING: this is copied from invrs/src/tasks/ubench.rs and must be
    // kept in sync!
    int maxParallelism = 100;
    try {
        for (const auto &i : numRequests) {
            for (int j = 0; j < numWarmupRepeats; j++) {
                runRequests(i, maxParallelism, maa);
            }

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

std::vector<int> parseIntList(const std::string &s) {
    std::vector<int> result;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        try {
            result.push_back(std::stoi(item));
        } catch (const std::invalid_argument &e) {
            std::cerr << "Invalid integer in list: " << item << std::endl;
        } catch (const std::out_of_range &e) {
            std::cerr << "Integer out of range in list: " << item << std::endl;
        }
    }
    return result;
}

int main(int argc, char **argv) {
    bool maa = false;
    std::vector<int> numRequests;
    int numWarmupRepeats = 1;
    int numRepeats = 3;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--maa") {
            maa = true;
        } else if (arg == "--num-requests") {
            if (i + 1 < argc) {
                numRequests = parseIntList(argv[++i]);
            } else {
                std::cerr << "--num-requests option requires one argument."
                          << std::endl;
                return 1;
            }
        } else if (arg == "--num-warmup-repeats") {
            if (i + 1 < argc) {
                numWarmupRepeats = std::stoi(argv[++i]);
            } else {
                std::cerr
                    << "--num-warmup-repeats option requires one argument."
                    << std::endl;
                return 1;
            }
        } else if (arg == "--num-repeats") {
            if (i + 1 < argc) {
                numRepeats = std::stoi(argv[++i]);
            } else {
                std::cerr << "--num-repeats option requires one argument."
                          << std::endl;
                return 1;
            }
        }
    }

    if (numRequests.empty()) {
        std::cerr << "Missing mandatory argument --num-requests" << std::endl;
        return 1;
    }

    doBenchmark(numRequests, numWarmupRepeats, numRepeats, maa);

    return 0;
}

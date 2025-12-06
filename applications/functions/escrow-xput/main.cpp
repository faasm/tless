#include "maa.h"

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

#include "maa.h"

#include "accless/abe4/abe4.h"
#include "accless/attestation/attestation.h"
#include "accless/attestation/ec_keypair.h"
#include "accless/base64/base64.h"
#include "accless/jwt/jwt.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <semaphore>
#include <sstream>
#include <thread>
#include <vector>

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string sendSingleAcclessRequest(const std::string &asUrl,
                                     const std::string &asCertPath,
                                     const std::vector<uint8_t> &report,
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
        asUrl, asCertPath, accless::attestation::snp::getAsEndpoint(false),
        body);
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
std::chrono::duration<double>
runRequests(int numRequests, int maxParallelism,
            const std::vector<std::string> &asUrls,
            const std::vector<std::string> &asCertPaths) {
    // =======================================================================
    // CP-ABE Preparation
    // =======================================================================

    // Get the ID and MPK we need to encrypt ciphertexts with attributes from
    // this attestation service instance.
    std::vector<std::string> ids;
    std::vector<std::string> partialMpks;
    for (size_t i = 0; i < asUrls.size(); ++i) {
        auto [id, partialMpk] =
            accless::attestation::getAttestationServiceState(asUrls[i],
                                                             asCertPaths[i]);
        ids.push_back(id);
        partialMpks.push_back(partialMpk);
    }
    std::string mpk = accless::abe4::packFullKey(ids, partialMpks);

    std::string gid = "baz";
    std::string wfId = "foo";
    std::string nodeId = "bar";

    // Pick the simplest policy that only relies on the attributes `wf` and
    // `node` which are provided by the attestation-service after a succesful
    // remote attestation. We do a conjunction over all registered attestation
    // services, in order to improve throughput by load-balancing.
    std::string policy;
    for (size_t i = 0; i < ids.size(); ++i) {
        policy += "(" + ids[i] + ".wf:" + wfId + " & " + ids[i] +
                  ".node:" + nodeId + ")";
        if (i < ids.size() - 1) {
            policy += " | ";
        }
    }

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

        threads.emplace_back([&semaphore, &asUrls, &asCertPaths, &report,
                              &reportDataVec, &gid, &wfId, &nodeId, i,
                              numAs = asUrls.size()]() {
            auto response = sendSingleAcclessRequest(
                asUrls[i % numAs], asCertPaths[i % numAs], report,
                reportDataVec, gid, wfId, nodeId);
            // And releasing when the thread is done.
            semaphore.release();
        });
    }

    // Send one request out of the loop, to easily process the result.
    auto response = sendSingleAcclessRequest(asUrls[0], asCertPaths[0], report,
                                             reportDataVec, gid, wfId, nodeId);

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
    std::string uskB64 = accless::abe4::packFullKey(ids, {partialUskB64});

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
                 int numRepeats, bool maa, const std::string &resultsFile,
                 const std::string &maaUrl,
                 const std::vector<std::string> &asUrls,
                 const std::vector<std::string> &asCertPaths) {
    // Write elapsed time to CSV
    std::ofstream csvFile(resultsFile, std::ios::out);
    csvFile << "NumRequests,TimeElapsed\n";

    int maxParallelism = 100;
    try {
        for (const auto &i : numRequests) {
            for (int j = 0; j < numWarmupRepeats; j++) {
                // Pre-warming is only necessary for regular Accless.
                if (!maa) {
                    runRequests(i, maxParallelism, asUrls, asCertPaths);
                }
            }

            for (int j = 0; j < numRepeats; j++) {
                std::chrono::duration<double> elapsedTimeSecs;
                if (maa) {
                    // We need lower parallelism because we share an AzClient
                    // instance among all client threads, so we must prevent
                    // race conditions.
                    elapsedTimeSecs = runMaaRequests(i, 10, maaUrl);
                } else {
                    elapsedTimeSecs =
                        runRequests(i, maxParallelism, asUrls, asCertPaths);
                }
                csvFile << i << "," << elapsedTimeSecs.count() << '\n';
            }
        }
    } catch (...) {
        std::cerr << "accless: error running benchmark" << std::endl;
        throw std::runtime_error("error running benchmark");
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
    std::string maaUrl;
    std::vector<int> numRequests;
    int numWarmupRepeats = 1;
    int numRepeats = 3;
    std::string resultsFile;
    std::vector<std::string> asUrls;
    std::vector<std::string> asCertPaths;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--maa") {
            maa = true;
        } else if (arg == "--maa-url") {
            if (i + 1 < argc) {
                maaUrl = argv[++i];
            } else {
                std::cerr << "--maa-url option requires one argument."
                          << std::endl;
                return 1;
            }
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
        } else if (arg == "--results-file") {
            if (i + 1 < argc) {
                resultsFile = argv[++i];
            } else {
                std::cerr << "--results-file option requires one argument."
                          << std::endl;
                return 1;
            }
        } else if (arg == "--as-urls") {
            if (i + 1 < argc) {
                asUrls = split(argv[++i], ',');
            } else {
                std::cerr << "--as-urls option requires one argument."
                          << std::endl;
                return 1;
            }
        } else if (arg == "--as-cert-paths") {
            if (i + 1 < argc) {
                asCertPaths = split(argv[++i], ',');
            } else {
                std::cerr << "--as-cert-paths option requires one argument."
                          << std::endl;
                return 1;
            }
        }
    }

    if (maa && maaUrl.empty()) {
        std::cerr << "Usage: --maa-url is mandatory when --maa is set"
                  << std::endl;
        return 1;
    }

    if (!maa && (asUrls.empty() || asCertPaths.empty())) {
        std::cerr << "Usage: --as-urls and --as-cert-paths are mandatory when "
                     "--maa is not set"
                  << std::endl;
        return 1;
    }

    if (numRequests.empty()) {
        std::cerr << "Missing mandatory argument --num-requests" << std::endl;
        return 1;
    }

    doBenchmark(numRequests, numWarmupRepeats, numRepeats, maa, resultsFile,
                maaUrl, asUrls, asCertPaths);

    return 0;
}

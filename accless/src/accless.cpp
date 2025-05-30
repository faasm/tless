#include "accless.h"
#include "aes.h"
#include "dag.h"
#include "jwt.h"
#include "rabe.h"
#include "utils.h"

#ifdef __faasm
// Faasm includes
#include <faasm/core.h>
#else
#include "attestation/attestation.h"
#include "s3/S3Wrapper.hpp"
#endif

#include <iostream>
#ifdef ACCLESS_UBENCH
#include <chrono>
#endif
#include <string>
#include <utility>
#include <vector>

#define AES256CM_NONCE_SIZE 12

#ifdef ACCLESS_UBENCH
typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimePoint;
std::vector<std::pair<std::string, TimePoint>> timePoints;

#define NOW std::chrono::high_resolution_clock::now()

void prettyPrintTimePoints() {
    TimePoint prevTimePoint;
    std::string prevLabel;

    std::cout << "###################### Accless Timing #####################"
              << std::endl;
    for (const auto &[label, tp] : timePoints) {
        if (!prevLabel.empty()) {
            std::chrono::duration<double, std::milli> duration =
                tp - prevTimePoint;
            std::cout << prevLabel << " to " << label << ": "
                      << duration.count() << " ms" << std::endl;
        }

        prevLabel = label;
        prevTimePoint = tp;
    }

    std::chrono::duration<double, std::milli> total =
        timePoints.at(timePoints.size() - 1).second - timePoints.at(0).second;
    std::cout << "Total: " << total.count() << " ms" << std::endl;
    std::cout << "###########################################################"
              << std::endl;
}

#endif

namespace accless {
bool on() {
#ifdef __faasm
    // Returns 0 if Accless features are enabled
    return __accless_is_enabled() == 0;
#else
    const char *envVar = std::getenv("ACCLESS_MODE");
    if (envVar && (std::string(envVar) == "on")) {
        return true;
    }

    return false;
#endif
}

// Specific per-TEE mechanism to get attestation:
// 1. For SGX-Faasm, we manually call the SGX routines in the SGX SDK
// 2. For SNP, two options:
//  2.1. Bare metal: query /dev/sev-guest (with `snpguest` crate?)
//  2.2. Use Azure's guest attestation library
//  TODO: in both cases, not clear we can do this from inside the confidential
//  container?
//
// In both cases, we get an attestation report and send it to the MAA for
// validation.
static bool validHardwareAttestation(std::string &jwtStrOut) {
#ifdef __faasm
    // Get SGX quote and send it to the attestation service, get JWT in return
#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("get-hw-att-begin", NOW));
#endif
    char *jwt;
    int32_t jwtSize;
    __accless_get_attestation_jwt(&jwt, &jwtSize);
    std::string jwtStr(jwt);
#else
    // TODO: instead of a nullopt we can pass a public key here
    auto snpReport = accless::attestation::getSnpReport(std::nullopt);
    std::string jwtStr = accless::attestation::asGetJwtFromReport(snpReport);
#endif

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("get-hw-att-end", NOW));
#endif

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("hw-att-validate-begin", NOW));
#endif

    // Verify JWT signature
    bool valid = accless::jwt::verify(jwtStr);
    if (!valid) {
        std::cout << "accless: error: failed to verify the signature in the JWT"
                  << std::endl;
        return false;
    }

    // Check signed JWT comes from the expected attestation service
    if (!accless::jwt::checkProperty(jwtStr, "aud", ATT_PROVIDER_AUD)) {
        std::cout << "accless: error: failed to validate JWT AUD" << std::endl;
        return false;
    } else if (!accless::jwt::checkProperty(jwtStr, "sub", ATT_PROVIDER_SUB)) {
        std::cout << "accless: error: failed to validate JWT AUD" << std::endl;
        return false;
#ifdef __faasm
    } else if (!accless::jwt::checkProperty(jwtStr, "tee", "sgx")) {
#else
    } else if (!accless::jwt::checkProperty(jwtStr, "tee", "snp")) {
#endif
        std::cout << "accless: error: failed to validate tee" << std::endl;
        return false;
    }

#ifdef __faasm
    // Sanity check: compare the MRENCLAVE with the one in the JWT. We rely
    // on the untrusted host to actually validate the JWT, so we want to
    // make sure that this JWT includes our actual MRENCLAVE. We need to convert
    // the raw bytes from the measurement to a hex string
    std::vector<uint8_t> mrEnclave(MRENCLAVE_SIZE);
    __accless_get_mrenclave(mrEnclave.data(), mrEnclave.size());
    std::string mrEnclaveHex = accless::utils::byteArrayToHexString(
        mrEnclave.data(), mrEnclave.size());
    /* TODO: attestation-service still cannot parse SGX reports
    if (!accless::jwt::checkProperty(jwt, "sgx-mrenclave", mrEnclaveHex)) {
        std::cout << "accless: error: failed to validate MrEnclave" <<
    std::endl; return false;
    }
    */
#else
    // For SNP, will we run on bare metal or in the cloud?
#endif

    // FIXME(accless-prod): as a consequence of a valid attestation, the MAA
    // would have provided us with the TEE shared identity, wrapped in the
    // public key we provide as part of the enclave held data of the report.
    // We still do not have implemented this functionality in the MAA

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("hw-att-validate-end", NOW));
#endif

    jwtStrOut = jwtStr;

    return true;
}

/* TLess chain validation protocol
 * 0. Get execution request
 * 1. Get TEE certificate:
 *  1.1. Get SGX quote
 *  1.2. Send it to Microsoft's Attestation Service, and get a JWT in return
 *  1.3. Validate that the JWT comes from Microsofr, and get
 */
bool checkChain(const std::string &workflow, const std::string &function,
                int id) {
    if (!on()) {
        return true;
    }

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("begin", NOW));
#endif

#ifndef __faasm
    s3::initS3Wrapper();
    s3::S3Wrapper s3cli;
#endif

    // -----------------------------------------------------------------------
    // 0. Fetch DAG
    // 0.1. Get DAG string from S3
    // 0.2. Calculate DAG hex digest
    // -----------------------------------------------------------------------

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("begin-fetch-exec-req", NOW));
#endif

    std::vector<uint8_t> serializedDag;
    std::string dagKey = workflow + "/dag";
#ifdef __faasm
    serializedDag = accless::utils::doGetKeyBytes("tless", dagKey);
#else
    serializedDag = s3cli.getKeyBytes("tless", dagKey);
#endif
    auto dag = accless::dag::deserialize(serializedDag);

    // Also calculate the hex-digest of the serialized DAG
    std::vector<uint8_t> hashedDag = accless::sha256::hash(serializedDag);
    std::string dagHexDigest = accless::utils::byteArrayToHexString(
        hashedDag.data(), hashedDag.size());

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("end-fetch-exec-req", NOW));
#endif

    // -----------------------------------------------------------------------
    // 1. Get TEE certificate
    // 1.1. Generate HW quote w/ public key
    // 1.2. Send quote to attestation-service (AA) for validation
    // 1.3. Receive quote and valiate signature AA signature and claims
    //
    // Note that the AA can validate both SGX and SNP quotes, so we take
    // advantage of that
    // -----------------------------------------------------------------------

    std::string jwtStr;
    if (!validHardwareAttestation(jwtStr)) {
        std::cout << "accless: error validating hw attestation" << std::endl;
        return false;
    }

    std::string teeIdentity = accless::jwt::getProperty(jwtStr, "tee_identity");

    // -----------------------------------------------------------------------
    // 2. Bootstrap CP-ABE context
    // 2.1. Fetch encrypted context
    // 2.2. Decrypt it with the TEE key that we obtained after attestation
    // -----------------------------------------------------------------------

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("begin-fetch-dec-cpabe", NOW));
#endif

    std::string teeSymKeyBase64 =
        accless::jwt::getProperty(jwtStr, "aes_key_b64");
    auto teeSymKey = accless::utils::base64Decode(teeSymKeyBase64);

    // Fetch the (encrypted) CP-ABE context from S3
    std::vector<uint8_t> ctCtx;
    // This key is hard-coded in invrs/src/tasks/dag.rs
    std::string cpAbeCtxKey = workflow + "/crypto/cp-abe-ctx";
#ifdef __faasm
    ctCtx = accless::utils::doGetKeyBytes("tless", cpAbeCtxKey);
#else
    ctCtx = s3cli.getKeyBytes("tless", cpAbeCtxKey);
#endif

    // Decrypt the CP-ABE context
    std::vector<uint8_t> nonceCtx(ctCtx.begin(),
                                  ctCtx.begin() + AES256CM_NONCE_SIZE);
    std::vector<uint8_t> ctCtxTrimmed(ctCtx.begin() + AES256CM_NONCE_SIZE,
                                      ctCtx.end());
    auto ptCtx = accless::aes256gcm::decrypt(teeSymKey, nonceCtx, ctCtxTrimmed);

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("end-fetch-dec-cpabe", NOW));
#endif

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("begin-fetch-dec-cert-chain", NOW));
#endif

    // Fetch the certificate chain for us. The certificate chain is wrapped
    // around an AES-encrypted bundle, and then CP-ABE encrypted
    std::vector<uint8_t> ctAesCertChain;
    // TODO: for the time being, we all share one cert-chain to measure the
    // overheads of TLess, albeit not fully functional
    // std::string certChainKey = workflow + "/cert-chain/" + function;
    std::string certChainKey = workflow + "/cert-chains/test";
#ifdef __faasm
    ctAesCertChain = accless::utils::doGetKeyBytes("tless", certChainKey);
#else
    ctAesCertChain = s3cli.getKeyBytes("tless", certChainKey);
#endif

    // Decrypt the AES bundle around certificate chain
    std::vector<uint8_t> nonceCertChain(
        ctAesCertChain.begin(), ctAesCertChain.begin() + AES256CM_NONCE_SIZE);
    std::vector<uint8_t> ctCertChain(
        ctAesCertChain.begin() + AES256CM_NONCE_SIZE, ctAesCertChain.end());
    auto ptAesCertChain =
        accless::aes256gcm::decrypt(teeSymKey, nonceCertChain, ctCertChain);

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("end-fetch-dec-cert-chain", NOW));
#endif

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("begin-gen-ecf-id", NOW));
#endif

    // Initialize CP-ABE context
    auto &ctx = accless::abe::CpAbeContextWrapper::get(
        accless::abe::ContextFetchMode::FromBytes, ptCtx);

    // Generate our set of attributes from the place we occupy in the dag
    std::vector<std::string> attributes = {teeIdentity, dagHexDigest};
    // TODO: this does not work well for functions with more than one parent!
    auto expectedChain = accless::dag::getCallChain(dag, function);

    // TODO(accless-prod): attributes should be derived from the chaining
    // message, not from the DAG itself
    for (int i = 0; i < expectedChain.size() - 1; i++) {
        attributes.push_back(expectedChain.at(i));
    }

    // Now use our attributes to decrypt the actual contents of the cert chain
    auto certChain = ctx.cpAbeDecrypt(attributes, ptAesCertChain);
    if (certChain.empty()) {
        std::cerr << "accless: error decrypting certificate chain" << std::endl;
        return false;
    }

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("end-gen-ecf-id", NOW));
#endif

    // Note that, succesful validation, implies that the function is called
    // in the right order. That being said, we double-check it here too
    std::vector<std::string> actualChain =
        accless::dag::getFuncChainFromCertChain(certChain);
    /* TODO: un-comment this checks when we properly propagate messages
    if (actualChain.size() != expectedChain.size()) {
        std::cerr << "accless: error: size mismatch between expected ("
                  << expectedChain.size()
                  << ") and actual ("
                  << actualChain.size()
                  << ") chains"
                  << std::endl;
        return false;
    }
    for (int i = 0; i < actualChain.size(); i++) {
        if (i == 0) {
            if (actualChain.at(0) != TLESS_CHAIN_GENESIS) {
                std::cerr << "accless: error: certificate chain has wrong
    beginning" << std::endl; return false;
            }
        } else {
            if (actualChain.at(i) != expectedChain.at(i - 1)) {
                std::cerr << "accless: error in cert chain (got: "
                          << actualChain.at(i)
                          << " - expected: "
                          << expectedChain.at(i - 1)
                          << ")" << std::endl;
                return false;
            }
        }
    }
    if (expectedChain.at(expectedChain.size() - 1) != function) {
        std::cerr << "accless: error in cert chain (got: "
                  << expectedChain.at(expectedChain.size() - 1)
                  << " - expected: "
                  << function
                  << ")" << std::endl;
        return false;
    }
    */

    std::cout << "accless: certificate chain validated!" << std::endl;

#ifdef ACCLESS_UBENCH
    timePoints.push_back(std::make_pair("end", NOW));
    prettyPrintTimePoints();
#endif

    return true;
}

int32_t chain(const std::string &workflow, const std::string &parentFuncName,
              int parentIdx, const std::string &funcName, int idx,
              const std::string &inputData) {
    if (!on()) {
#ifdef __faasm
        return faasmChainNamed(funcName.c_str(), (uint8_t *)inputData.c_str(),
                               inputData.size());
#else
        return 0;
#endif
    }

    std::cout << "accless(chain): extending certificate chain and chaining"
              << std::endl;

    // TODO: actually propagate the certificate chain
    std::string key = workflow + "/cert-chains/" + funcName + "-" +
                      std::to_string(parentIdx) + "-" + std::to_string(idx);
    std::string keyBytes = "UPDATE_ME";
#ifdef __faasm
    accless::utils::doAddKeyBytes("tless", key, keyBytes);
#else
    s3::initS3Wrapper();
    s3::S3Wrapper s3cli;
    s3cli.addKeyStr("tless", key, keyBytes);
#endif

#ifdef __faasm
    return faasmChainNamed(funcName.c_str(), (uint8_t *)inputData.c_str(),
                           inputData.size());
#else
    return 0;
#endif
}

#ifdef __faasm
std::pair<int, std::string> wait(int32_t functionId, bool ignoreOutput) {
    if (!on()) {
        if (!ignoreOutput) {
            // TODO: think about memory ownership here
            char *output;
            int outputLen;
            int result = faasmAwaitCallOutput(functionId, &output, &outputLen);

            return std::make_pair(result, output);
        }

        int result = faasmAwaitCall(functionId);
        return std::make_pair(result, "");
    }

    return std::make_pair(-1, "");
}
#endif
} // namespace accless

#include "tless.h"
// Both tless::aes256gcm and tles::sha256 are declared in this header
#include "tless_aes.h"
#ifdef __faasm
// For the time being, this library is only needed in Faasm
#include "tless_jwt.h"
#endif
#include "tless_abe.h"
#include "dag.h"
#include "utils.h"

// Faasm includes
#ifdef __faasm
#include <faasm/core.h>
#else
#include "../s3/S3Wrapper.hpp"
#endif

#include <iostream>
#include <string>
#include <vector>
#include <utility>

#define AES256CM_NONCE_SIZE 12

// FIXME(tless-prod): this symmetric key is shared by all TEEs, and would be
// provided by the MAA upon succesful attestation
std::vector<uint8_t> DEMO_SYM_KEY = {
    0xf0, 0x0d, 0x48, 0x2e, 0xca, 0x21, 0xfb, 0x13,
    0xec, 0xf0, 0x01, 0x48, 0xba, 0x60, 0x01, 0x76,
    0x6e, 0x56, 0xbb, 0xa5, 0xff, 0x9b, 0x11, 0x9d,
    0xd6, 0xfa, 0x96, 0x39, 0x2b, 0x7c, 0x1a, 0x0d
};

namespace tless {
bool on()
{
#ifdef __faasm
    // Returns 0 if TLess features are enabled
    return __tless_is_enabled() == 0;
#else
    return true;
#endif
}

// Specific per-TEE mechanism to get attestation
static bool validHardwareAttestation()
{
#ifdef __faasm
    // Get SGX quote and send it to MAA, get JWT in return
    char* jwt;
    int32_t jwtSize;
    __tless_get_attestation_jwt(&jwt, &jwtSize);
    std::string jwtStr(jwt);

    // Verify JWT signature
    bool valid = tless::jwt::verify(jwtStr);
    if (!valid) {
        return false;
    }

    // Check signed JWT comes from the expected attestation service and has
    // the same MRENCLAVE we do
    if (!tless::jwt::checkProperty(jwt, "jku", ATT_PROVIDER_JKU)) {
        std::cout << "Failed to validate JWT JKU" << std::endl;
        return false;
    }

    // To compare the MRENCLAVE with the one in the JWT, we need to convert
    // the raw bytes from the measurement to a hex string
    std::vector<uint8_t> mrEnclave(MRENCLAVE_SIZE);
    __tless_get_mrenclave(mrEnclave.data(), mrEnclave.size());
    std::string mrEnclaveHex = tless::utils::byteArrayToHexString(mrEnclave.data(), mrEnclave.size());
    if (!tless::jwt::checkProperty(jwt, "sgx-mrenclave", mrEnclaveHex)) {
        std::cout << "Failed to validate MrEnclave" << std::endl;
        return false;
    }

    // FIXME(tless-prod): as a consequence of a valid attestation, the MAA
    // would have provided us with the TEE shared identity, wrapped in the
    // public key we provide as part of the enclave held data of the report.
    // We still do not have implemented this functionality in the MAA
#else
    // For SNP we could just use snpguest crate from here
#endif

    return true;
}


/* TLess chain validation protocol
 * 0. Get execution request
 * 1. Get TEE certificate:
 *  1.1. Get SGX quote
 *  1.2. Send it to Microsoft's Attestation Service, and get a JWT in return
 *  1.3. Validate that the JWT comes from Microsofr, and get
 */
bool checkChain(const std::string& workflow, const std::string& function, int id)
{
    // TODO: we must add this method at the entrypoint of _each_ function
    if (!on()) {
        return true;
    }

#ifndef __faasm
    s3::initS3Wrapper();
    s3::S3Wrapper s3cli;
#endif

    // -----------------------------------------------------------------------
    // 0. Fetch DAG
    // 0.1. Get DAG string from S3
    // 0.2. Calculate DAG hex digest
    // -----------------------------------------------------------------------

    std::vector<uint8_t> serializedDag;
    std::string dagKey = workflow + "/dag";
#ifdef __faasm
    serializedDag = tless::utils::doGetKeyBytes("tless", dagKey);
#else
    serializedDag = s3cli.getKeyBytes("tless", dagKey);
#endif
    auto dag = tless::dag::deserialize(serializedDag);

    // Also calculate the hex-digest of the serialized DAG
    std::vector<uint8_t> hashedDag = tless::sha256::hash(serializedDag);
    std::string dagHexDigest = tless::utils::byteArrayToHexString(hashedDag.data(), hashedDag.size());

    // -----------------------------------------------------------------------
    // 1. Get TEE certificate
    // 1.1. Generate quote w/ public key for MAA
    // 1.2. Send quote to MAA for validation
    // 1.3. Receive quote and valiate signature
    // -----------------------------------------------------------------------

    if (!validHardwareAttestation()) {
        return false;
    }

    // FIXME(tless-prod): this value would be returned by the MAA upon a
    // succesful attestation, encrypted with the public key we provided as
    // part of the original attestation bundle
    std::string teeIdentity = "G4NU1N3TL3SST33";

    // -----------------------------------------------------------------------
    // 2. Bootstrap CP-ABE context
    // 2.1. Fetch encrypted context
    // 2.2. Decrypt it with the TEE identity that we obtained from the previous
    //      step
    // -----------------------------------------------------------------------

    // Fetch the (encrypted) CP-ABE context from S3
    std::vector<uint8_t> ctCtx;
    // This key is hard-coded in tlessctl/src/tasks/dag.rs
    std::string cpAbeCtxKey = workflow + "/crypto/cp-abe-ctx";
#ifdef __faasm
    ctCtx = tless::utils::doGetKeyBytes("tless", cpAbeCtxKey);
#else
    ctCtx = s3cli.getKeyBytes("tless", cpAbeCtxKey);
#endif

    // Decrypt the CP-ABE context
    std::vector<uint8_t> nonceCtx(ctCtx.begin(), ctCtx.begin() + AES256CM_NONCE_SIZE);
    std::vector<uint8_t> ctCtxTrimmed(ctCtx.begin() + AES256CM_NONCE_SIZE, ctCtx.end());
    auto ptCtx = tless::aes256gcm::decrypt(DEMO_SYM_KEY, nonceCtx, ctCtxTrimmed);

    // Initialize CP-ABE context
    auto& ctx = tless::abe::CpAbeContextWrapper::get(tless::abe::ContextFetchMode::FromBytes, ptCtx);

    // Generate our set of attributes from the place we occupy in the dag
    std::vector<std::string> attributes = {teeIdentity, dagHexDigest};
    // TODO: this does not work well for functions with more than one parent!
    auto expectedChain = tless::dag::getCallChain(dag, function);

    for (int i = 0; i < expectedChain.size() - 1; i++) {
        attributes.push_back(expectedChain.at(i));
    }

    // Fetch the certificate chain for us. The certificate chain is wrapped
    // around an AES-encrypted bundle, and then CP-ABE encrypted
    std::vector<uint8_t> ctAesCertChain;
    std::string certChainKey = workflow + "/cert-chain/" + function;
#ifdef __faasm
    ctAesCertChain = tless::utils::doGetKeyBytes("tless", certChainKey);
#else
    ctAesCertChain = s3cli.getKeyBytes("tless", certChainKey);
#endif

    // Decrypt the AES bundle around certificate chain
    std::vector<uint8_t> nonceCertChain(ctAesCertChain.begin(), ctAesCertChain.begin() + AES256CM_NONCE_SIZE);
    std::vector<uint8_t> ctCertChain(ctAesCertChain.begin() + AES256CM_NONCE_SIZE, ctAesCertChain.end());
    auto ptAesCertChain = tless::aes256gcm::decrypt(DEMO_SYM_KEY, nonceCertChain, ctCertChain);

    // Now use our attributes to decrypt the actual contents of the cert chain
    auto certChain = ctx.cpAbeDecrypt(attributes, ptAesCertChain);
    if (certChain.empty()) {
        std::cerr << "tless: error decrypting certificate chain" << std::endl;
        return false;
    }

    // Note that, succesful validation, implies that the function is called
    // in the right order. That being said, we double-check it here too
    std::vector<std::string> actualChain = tless::dag::getFuncChainFromCertChain(certChain);
    if (actualChain.size() != expectedChain.size()) {
        std::cerr << "tless: error: validating certificate chain" << std::endl;
        return false;
    }
    for (int i = 0; i < actualChain.size(); i++) {
        if (i == 0) {
            if (actualChain.at(0) != TLESS_CHAIN_GENESIS) {
                std::cerr << "tless: error: certificate chain has wrong beginning" << std::endl;
                return false;
            }
        } else {
            if (actualChain.at(i) != expectedChain.at(i - 1)) {
                std::cerr << "tless: error in cert chain (got: "
                          << actualChain.at(i)
                          << " - expected: "
                          << expectedChain.at(i - 1)
                          << ")" << std::endl;
                return false;
            }
        }
    }
    if (expectedChain.at(expectedChain.size() - 1) != function) {
        std::cerr << "tless: error in cert chain (got: "
                  << expectedChain.at(expectedChain.size() - 1)
                  << " - expected: "
                  << function
                  << ")" << std::endl;
        return false;
    }

    std::cout << "tless: certificate chain validated!" << std::endl;

    // -----------------------------------------------------------------------
    // 3. Get execution token
    // 3.1. Fetch execution token from storage
    // 3.2. Decrypt function code
    // -----------------------------------------------------------------------

    std::cout << "still VERY VERY strong!" << std::endl;

#ifndef __faasm
    s3::shutdownS3Wrapper();
#endif

    return true;
}

int32_t chain(const std::string& funcName, const std::string& inputData)
{
    if (!on()) {
#ifdef __faasm
        return faasmChainNamed(funcName.c_str(), (uint8_t*) inputData.c_str(), inputData.size());
#else
        return 0;
#endif
    }

    // Here, upload the new certificate chain to {workflow}/cert-chain/{func_name}

#ifdef __faasm
    return faasmChainNamed(funcName.c_str(), (uint8_t*) inputData.c_str(), inputData.size());
#else
    return 0;
#endif
}

#ifdef __faasm
std::pair<int, std::string> wait(int32_t functionId, bool ignoreOutput)
{
    if (!on()) {
        if (!ignoreOutput) {
            // TODO: think about memory ownership here
            char* output;
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
}

#include <AttestationClient.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

#include "logger.h"
#include "utils.h"

using json = nlohmann::json;

std::vector<std::string> split(const std::string& str, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string token;

    while (std::getline(ss, token, delim)) {
        result.push_back(token);
    }

    return result;
}

/*
 * Fetch the HW attestation report from the vTPM, send it to the Azure
 * Attestation evidence, and return a JWT.
 */
std::string fetchHwAttReportGetAzJwt(const std::string& attestationUrl)
{
    assert(!attestationUrl.empty());

    if (output_type.empty()) {
        // set the default output type to boolean
        output_type = OUTPUT_TYPE_BOOL;
    }

    AttestationClient* attestationClient = nullptr;
    Logger* logHandle = new Logger();

    // Initialize attestation client
    if (!Initialize(logHandle, &attestationClient)) {
        std::cerr << "accless: failed to create attestation client object" << std::endl;
        Uninitialize();
        throw std::runtime_error("failed to create attestation client object");
    }

    // parameters for the Attest call
    attest::ClientParameters params = {};
    params.attestation_endpoint_url = (unsigned char*)attestationUrl.c_str();
    // TODO: can we add a public key here?
    std::string clientPayload = "{\"nonce\":\"" + nonce + "\"}";
    params.client_payload = (unsigned char*) client_payload_str.c_str();
    params.version = CLIENT_PARAMS_VERSION;

    bool is_cvm = false;
    bool attestation_success = true;
    std::string jwt_str;
    // call attest

    unsigned char* jwt = nullptr;
    auto attResult = attestationClient->Attest(params, &jwt);
    if (attResult.code_ != attest::AttestationResult::ErrorCode::SUCCESS) {
        std::cerr << "accless: error getting attestation from attestation client" << std::endl;
        Uninitialize();
        throw std::runtime_error("failed to get attestation from attestation client");
    }

    std::string jwtStr = reinterpret_cast<char*>(jwt);
    attestation_client->Free(jwt);
    Uninitialize();

    std::cout << "accless: debug: got jwtStr: " << jwtStr << std::endl;
    return jwtStr;
}

void validateJwtClaims(const std::string& jwtStr)
{
    // Prase attestation token to extract isolation tee details
    auto tokens = split(jwtStr, ".");
    if (tokens.size() < 3) {
        std::cerr << "accless: error validating jwt: not enough tokens" << std::endl;
        throw std::runtime_error("accless: error validating jwt");
    }

    json attestationClaims = json::parse(base64decode(tokens[1]));
    std::string attestationType;
    std::string compliance_status;
    try {
        attestationType = attestationClaims["x-ms-isolation-tee"]["x-ms-attestation-type"].get<std::string>();
        complianceStatus = attestationClaims["x-ms-isolation-tee"]["x-ms-compliance-status"].get<std::string>();
    } catch (...) {
        std::cerr << "accless: jwt does not have the expected claims" << std::endl;
        throw std::runtime_error("accless: error validating jwt");
    }

    if !((attestationType == "sevsnpvm") && (complianceStatus == "azure-compliant-cvm")) {
        std::cerr << "accless: jwt validation does not pass" << std::endl;
    }

    std::cout << "accless: jwt validation passed" << std::endl;
}


int main()
{
    // TODO: attest MAA

    // Initialize CP-ABE ctx (don't count time)
    // TODO: discard this if its making us lose time
    auto& ctx = tless::abe::CpAbeContextWrapper::get(tless::abe::ContextFetchMode::Create);

    // Fetch the HW att. report from vTPM and send it to AA to get a JWT
    auto jwtStr = fetchHwAttReportGetAzJwt("foobar");

    // TODO: validate JWT signature

    // Validate some of the claims in the JWT
    // TODO: somehow get the public key from the JWT
    validateJwtClaims(jwtStr);

    // TODO: use pub key to decrypt something

    // Generate our set of attributes from this something
    std::vector<std::string> attributes = {"foo", "bar"};
    std::vector<uint8_t> cipherText = {}; // TODO;
    auto certChain = ctx.cpAbeDecrypt(attributes, cipherText);
    if (certChain.empty()) {
        std::cerr << "accless: error decrypting certificate chain" << std::endl;
        throw std::runtime_error("error decrypting secret");
    }
}

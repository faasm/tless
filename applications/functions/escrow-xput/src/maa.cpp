/* Helper methods to interact with Microsoft's Azure Attestation Service */

/*
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
*/

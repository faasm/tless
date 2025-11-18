#pragma once

// Includes from Azure Guest Attestation library
#include "AttestationLogger.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace accless::attestation {

// FIXME(#44): eventually move this to an accless AES-GCM library.
constexpr size_t AES_128_KEY_SIZE = 16;
constexpr size_t AES_GCM_IV_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;

namespace utils {
// Helper methods
std::string extractJsonStringField(const std::string &json,
                                   const std::string &field);

/**
 * @brief Builds a JSON request body for attestation.
 *
 * This function constructs a JSON request body containing attestation-related
 * data, including a base64-encoded quote, runtime data, and node-specific
 * identifiers.
 *
 * @param quoteB64 The base64-encoded attestation quote.
 * @param runtimeB64 The base64-encoded runtime data.
 * @param gid The group ID of the node.
 * @param workflowId The workflow ID of the node.
 * @param nodeId The node ID.
 * @return A JSON string representing the request body.
 */
std::string buildRequestBody(const std::string &quoteB64,
                             const std::string &runtimeB64,
                             const std::string &gid,
                             const std::string &workflowId,
                             const std::string &nodeId);
} // namespace utils

// Mock helpers used in integration tests.
namespace mock {
std::string getMockSgxAttestationJwt();
std::string getMockSnpAttestationJwt();
} // namespace mock

// SNP-related methods
namespace snp {
// Utility methods
class Logger : public attest::AttestationLogger {
  public:
    void Log(const char *log_tag, attest::AttestationLogger::LogLevel level,
             const char *function, const int line, const char *fmt, ...);
};

/**
 * @brief Gets an attestation JWT for an SNP cVM.
 *
 * This function is the main entrypoint to run the attribute-minting protocol
 * for an SNP cVM. When called iniside an SNP cVM, this function will fetch
 * the hardware attestation report, generate an ephemeral keypair, and
 * initiate a remote attestation protocol with the attestation service. If
 * succesful, it will receive a key corresponding to the user, workflow and
 * node ids provided as arguments.
 *
 * @param gid The unique ID of the end-user.
 * @param workflowId The workflow ID of the node.
 * @param nodeId The node ID.
 * @return A JSON string representing the JWT.
 */
std::string getAttestationJwt(const std::string &gid,
                              const std::string &workflowId,
                              const std::string &nodeId);
} // namespace snp

// Attestation-service methods
std::string getAttestationServiceUrl();
std::string getAttestationServiceCertPath();
std::pair<std::string, std::string> getAttestationServiceState();
std::string getJwtFromReport(const std::string &endpoint,
                             const std::string &reportJson);
std::string decryptJwt(const std::vector<uint8_t> &encrypted,
                       const std::vector<uint8_t> &aesKey);
} // namespace accless::attestation

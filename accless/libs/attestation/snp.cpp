#include "attestation.h"
#include "base64.h"
#include "ec_keypair.h"
#include "mock.h"

// Includes from Azure Guest Attestation library
#include "AttestationLogger.h"
#include "HclReportParser.h"
#include "TpmCertOperations.h"

#include <array>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <vector>
#include <stdexcept> // Added for std::runtime_error
#include <iostream>  // Added for std::cerr and std::endl

using namespace attest;

#define SNP_GUEST_REQ_IOC_TYPE 'S'
#define SNP_GET_REPORT                                                         \
    _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x0, struct snp_guest_request_ioctl)

// We copy this structures from:
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/sev-guest.h#L80
constexpr size_t SNP_REPORT_USER_DATA_SIZE = 64;
constexpr size_t SNP_REPORT_RESP_SIZE = 4000;

struct snp_report_req {
    uint8_t user_data[SNP_REPORT_USER_DATA_SIZE];
    uint32_t vmpl;
    uint8_t rsvd[28];
};

struct snp_report_resp {
    uint8_t data[SNP_REPORT_RESP_SIZE];
};

struct snp_guest_request_ioctl {
    uint8_t msg_version;
    uint64_t req_data;
    uint64_t resp_data;
    union {
        uint64_t exitinfo2;
        struct {
            uint32_t fw_error;
            uint32_t vmm_error;
        };
    };
};

namespace accless::attestation::snp {
void Logger::Log(const char *log_tag, AttestationLogger::LogLevel level,
                 const char *function, const int line, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    size_t len = std::vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    std::vector<char> str(len + 1);

    va_start(args, fmt);
    std::vsnprintf(&str[0], len + 1, fmt, args);
    va_end(args);

    // Uncomment for debug logs
    // std::cout << std::string(str.begin(), str.end()) << std::endl;
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

// This method fetches the SNP attestation report from /dev/sev-guest:
// - message_version is not used in this simple example, but is kept for
// interface compatibility.
// - userData: Optional 64-byte data to be included in the report.
// - vmpl: Optional VMPL level.
std::vector<uint8_t>
getSnpReportFromDev(std::optional<std::array<uint8_t, 64>> userData,
                    std::optional<uint32_t> vmpl) {
    int fd = open("/dev/sev-guest", O_RDWR);
    if (fd < 0) {
        std::cerr << "accless(att): failed to open /dev/sev-guest" << std::endl;
        throw std::runtime_error("Failed to open /dev/sev-guest");
    }

    // Prepare the request payload.
    snp_report_req reqPayload;
    std::memset(&reqPayload, 0, sizeof(reqPayload));
    reqPayload.vmpl = vmpl.value_or(0);
    if (userData.has_value()) {
        std::memcpy(reqPayload.user_data, userData->data(), userData->size());
    }

    // Prepare the response buffer.
    snp_report_resp respPayload;
    std::memset(&respPayload, 0, sizeof(respPayload));

    // Prepare the ioctl wrapper.
    snp_guest_request_ioctl guestReq;
    std::memset(&guestReq, 0, sizeof(guestReq));
    guestReq.msg_version = 1; // Must be non-zero.
    guestReq.req_data = reinterpret_cast<uint64_t>(&reqPayload);
    guestReq.resp_data = reinterpret_cast<uint64_t>(&respPayload);

    // Issue the ioctl.
    if (ioctl(fd, SNP_GET_REPORT, &guestReq) < 0) {
        int err = errno;
        close(fd);
        std::cerr << "accless(att): ioctl SNP_GET_REPORT failed: "
                  << strerror(err) << std::endl;
        throw std::runtime_error("ioctl SNP_GET_REPORT failed");
    }
    close(fd);

    // Check for firmware or VMM errors.
    if (guestReq.fw_error != 0 || guestReq.vmm_error != 0) {
        std::cerr << "accless(att): firmware error: " << guestReq.fw_error
                  << " vmm error: " << guestReq.vmm_error << std::endl;
        throw std::runtime_error("Firmware reported error");
    }

    // Convert the response to a vector.
    std::vector<uint8_t> report(respPayload.data,
                                respPayload.data + SNP_REPORT_RESP_SIZE);
    return report;
}

std::vector<uint8_t>
getReport(std::array<uint8_t, 64> reportData) {
    if (std::filesystem::exists("/dev/sev-guest")) {
        return getSnpReportFromDev(reportData, std::nullopt);
    }

    if (std::filesystem::exists("/dev/tpmrm0")) {
        return getSnpReportFromTPM();
    }

    std::cerr << "accless(att): no known SNP device found for attestation"
              << std::endl;
    throw std::runtime_error("No known SNP device found!");
}

std::string getAttestationJwt(const std::string& gid,
                              const std::string& workflowId,
                              const std::string& nodeId)
{
    // Generate ephemeral EC keypair.
    accless::attestation::ec::EcKeyPair keyPair;

    // Get auxiliary report data: serialized public halve of the EC keypair.
    std::array<uint8_t, SGX_REPORT_DATA_SIZE> reportData = keyPair.getReportData();
    std::vector<uint8_t> reportDataVec(reportData.begin(), reportData.end());

    // Fetch HW attestation report and include the auxiliary report data in
    // the signature.
    std::vector<uint8_t> report;
    if (gid == mock::MOCK_GID) {
        report = accless::attestation::mock::buildMockQuote(reportDataVec, mock::MOCK_QUOTE_MAGIC_SNP);
    } else {
        report = getReport(reportData);
    }

    // Get the attestation service request body.
    std::string reportB64 = accless::base64::encodeUrlSafe(report);
    std::string runtimeDataB64 = accless::base64::encodeUrlSafe(reportDataVec);
    std::string body = accless::attestation::utils::buildRequestBody(reportB64, runtimeDataB64, gid, workflowId, nodeId);

    // Send the request, and get the response back.
    std::string response = accless::attestation::getJwtFromReport("/verify-snp-report", body);
    std::string encryptedB64 = accless::attestation::utils::extractJsonStringField(response, "encrypted_token");
    std::string serverKeyB64 = accless::attestation::utils::extractJsonStringField(response, "server_pubkey");

    // Decode response values.
    // FIXME: do we need URL safe here?
    std::vector<uint8_t> encrypted = accless::base64::decode(encryptedB64);
    std::vector<uint8_t> serverPubKey = accless::base64::decode(serverKeyB64);

    // Derive shared secret necessary to decrypt JWT.
    std::vector<uint8_t> sharedSecret = keyPair.deriveSharedSecret(serverPubKey);
    if (sharedSecret.size() < AES_128_KEY_SIZE) {
        throw std::runtime_error("accless(att): derived secret too small");
    }
    std::vector<uint8_t> aesKey(sharedSecret.begin(),
                                sharedSecret.begin() + AES_128_KEY_SIZE);

    // Decrypt JWT.
    return accless::attestation::decryptJwt(encrypted, aesKey);
}
} // namespace accless::attestation::snp

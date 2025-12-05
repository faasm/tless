#include "attestation.h"
#include "base64.h"
#include "ec_keypair.h"
#include "mock.h"

// Includes from Azure Guest Attestation library
#include "AttestationLibUtils.h"
#include "AttestationLogger.h"
#include "HclReportParser.h"
#include "Tpm.h"
#include "TpmCertOperations.h"

#include <array>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <openssl/sha.h>
#include <optional>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <vector>

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

// Helper method to append a little-endian u32 to a byte vector.
static void appendU32LE(std::vector<uint8_t> &out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

// Helper method to hash a byte array.
static std::vector<uint8_t> sha256(const std::vector<uint8_t> &data) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(digest.data(), &ctx);

    return digest;
}

/**
 * @brief Get SNP report from TPM.
 *
 * This function fetches the SNP report from a vTPM in an Azure cVM (i.e. a
 * para-virtualized environment). In Azure cVMs, the SNP report is generated
 * at boot, and cannot be modified. In order to include a fresh key inside the
 * report, we need to request a vTPM quote, and verify that it has been signed
 * by the vTPM's Attestation Key (AK) which is included in the report's
 * runtime_data. The vTPM quote has a message and a signature.
 *
 * Note that, even though the size of the runtime data (i.e. nonce) that we
 * can include in both SGX and SNP reports is 64 bytes, the nonce we can
 * include in the vTPM is only 32 bytes.
 *
 * We treat both the report and the vTPM quote as opaque blobs that we pass on
 * to the attestation service in a single serialized array with layout:
 * [0..3]   = reportLen (LE)
 * [4..7]   = msgLen    (LE)
 * [8..11]  = sigLen    (LE)
 * [12..]   = report || msg || sig
 */
std::vector<uint8_t>
getSnpReportFromTPM(const std::array<uint8_t, 64> &reportData) {
    Tpm tpm;

    // First, get HCL report.
    Buffer hclReport = tpm.GetHCLReport();

    // Second, get vTPM quote (note the hashing of the runtime data).
    PcrList pcrs = GetAttestationPcrList();
    PcrQuote quote = tpm.GetPCRQuoteWithNonce(
        pcrs, HashAlg::Sha256,
        sha256(std::vector<uint8_t>(reportData.begin(), reportData.end())));
    // quote.quote     = marshalled TPM2B_ATTEST
    // quote.signature = marshalled TPMT_SIGNATURE

    if (hclReport.size() > UINT32_MAX || quote.quote.size() > UINT32_MAX ||
        quote.signature.size() > UINT32_MAX) {
        throw std::runtime_error(
            "Evidence component too large to encode with u32 lengths");
    }

    uint32_t reportLen = static_cast<uint32_t>(hclReport.size());
    uint32_t quoteLen = static_cast<uint32_t>(quote.quote.size());
    uint32_t sigLen = static_cast<uint32_t>(quote.signature.size());

    std::vector<uint8_t> blob;
    blob.reserve(3 * sizeof(uint32_t) + reportLen + quoteLen + sigLen);

    // Layout:
    // [0..3]   = reportLen (LE)
    // [4..7]   = quoteLen    (LE)
    // [8..11]  = sigLen    (LE)
    // [12..]   = report || msg || sig

    appendU32LE(blob, reportLen);
    appendU32LE(blob, quoteLen);
    appendU32LE(blob, sigLen);

    blob.insert(blob.end(), hclReport.begin(), hclReport.end());
    blob.insert(blob.end(), quote.quote.begin(), quote.quote.end());
    blob.insert(blob.end(), quote.signature.begin(), quote.signature.end());

    return blob;
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

std::vector<uint8_t> getReport(std::array<uint8_t, 64> reportData) {
    if (std::filesystem::exists("/dev/sev-guest")) {
        return getSnpReportFromDev(reportData, std::nullopt);
    }

    if (std::filesystem::exists("/dev/tpmrm0")) {
        return getSnpReportFromTPM(reportData);
    }

    std::cerr << "accless(att): no known SNP device found for attestation"
              << std::endl;
    throw std::runtime_error("No known SNP device found!");
}

static std::string getAsEndpoint(bool isMock) {
    if (isMock) {
        return "/verify-snp-report";
    }

    if (std::filesystem::exists("/dev/sev-guest")) {
        return "/verify-snp-report";
    }

    if (std::filesystem::exists("/dev/tpmrm0")) {
        return "/verify-snp-vtpm-report";
    }

    std::cerr << "accless(att): no known SNP device found for attestation"
              << std::endl;
    throw std::runtime_error("No known SNP device found!");
}

std::string getAttestationJwt(const std::string &gid,
                              const std::string &workflowId,
                              const std::string &nodeId) {
    // Generate ephemeral EC keypair.
    accless::attestation::ec::EcKeyPair keyPair;

    // Get auxiliary report data: serialized public halve of the EC keypair.
    std::array<uint8_t, SNP_REPORT_USER_DATA_SIZE> reportData =
        keyPair.getReportData();
    std::vector<uint8_t> reportDataVec(reportData.begin(), reportData.end());

    // Fetch HW attestation report and include the auxiliary report data in
    // the signature.
    std::vector<uint8_t> report;
    // FIXME: consider making this check more reliable.
    bool isMock = (gid == mock::MOCK_GID);

    if (isMock) {
        std::cout << "accless(att): WARNING: mocking SNP quote" << std::endl;
        report = accless::attestation::mock::buildMockQuote(
            reportDataVec, mock::MOCK_QUOTE_MAGIC_SNP);
    } else {
        report = getReport(reportData);
    }

    // Get the attestation service request body.
    std::string reportB64 = accless::base64::encodeUrlSafe(report);
    std::string runtimeDataB64 = accless::base64::encodeUrlSafe(reportDataVec);
    std::string body = accless::attestation::utils::buildRequestBody(
        reportB64, runtimeDataB64, gid, workflowId, nodeId);

    // Send the request, and get the response back.
    std::string response =
        accless::attestation::getJwtFromReport(getAsEndpoint(isMock), body);
    std::string encryptedB64 =
        accless::attestation::utils::extractJsonStringField(response,
                                                            "encrypted_token");
    std::string serverKeyB64 =
        accless::attestation::utils::extractJsonStringField(response,
                                                            "server_pubkey");

    // Decode response values.
    std::vector<uint8_t> encrypted =
        accless::base64::decodeUrlSafe(encryptedB64);
    std::vector<uint8_t> serverPubKey =
        accless::base64::decodeUrlSafe(serverKeyB64);

    // Derive shared secret necessary to decrypt JWT.
    std::vector<uint8_t> sharedSecret =
        keyPair.deriveSharedSecret(serverPubKey);
    if (sharedSecret.size() < AES_128_KEY_SIZE) {
        throw std::runtime_error("accless(att): derived secret too small");
    }
    std::vector<uint8_t> aesKey(sharedSecret.begin(),
                                sharedSecret.begin() + AES_128_KEY_SIZE);

    // Decrypt JWT.
    return accless::attestation::decryptJwt(encrypted, aesKey);
}
} // namespace accless::attestation::snp

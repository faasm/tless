#include "attestation.h"

// Includes from Azure Guest Attestation library
#include "AttestationLogger.h"
#include "HclReportParser.h"
#include "TpmCertOperations.h"

#include <array>
#include <curl/curl.h>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <vector>

using namespace attest;

#define SNP_GUEST_REQ_IOC_TYPE 'S'
#define SNP_GET_REPORT _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x0, struct snp_guest_request_ioctl)

namespace accless::attestation {
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

/******************************************************************************/
/* SNP Related Methods                                                */
/******************************************************************************/

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
    guestReq.msg_version = 1;  // Must be non-zero.
    guestReq.req_data = reinterpret_cast<uint64_t>(&reqPayload);
    guestReq.resp_data = reinterpret_cast<uint64_t>(&respPayload);

    // Issue the ioctl.
    if (ioctl(fd, SNP_GET_REPORT, &guestReq) < 0) {
        int err = errno;
        close(fd);
        std::cerr << "accless(att): ioctl SNP_GET_REPORT failed: " << strerror(err) << std::endl;
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
    std::vector<uint8_t> report(respPayload.data, respPayload.data + SNP_REPORT_RESP_SIZE);
    return report;
}

std::vector<uint8_t>
getSnpReport(std::optional<std::array<uint8_t, 64>> reportData) {
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

/******************************************************************************/
/* Attestation Service Methods                                                */
/******************************************************************************/

// Get the URL of our own attestation service (**not** MAA)
std::string getAttestationServiceUrl() {
    const char *val = std::getenv("ACCLESS_ATTESTATION_SERVICE_URL");
    return val ? std::string(val) : "https://127.0.0.1:8443";
}

size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t totalSize = size * nmemb;
    auto *response = static_cast<std::string *>(userdata);
    response->append(ptr, totalSize);
    return totalSize;
}

std::string asGetJwtFromReport(const std::vector<uint8_t> &snpReport) {
    std::string jwt;

    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "accless: failed to initialize CURL" << std::endl;
        throw std::runtime_error("curl error");
    }

    std::string asUrl = getAttestationServiceUrl();
    curl_easy_setopt(curl, CURLOPT_URL, asUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(
        curl, CURLOPT_CAINFO,
        "/home/tless/git/faasm/tless/attestation-service/certs/cert.pem");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, snpReport.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, snpReport.size());

    struct curl_slist *headers = nullptr;
    headers =
        curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Set write function and data
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &jwt);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "accless: CURL error: " << curl_easy_strerror(res)
                  << std::endl;
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        throw std::runtime_error("curl error");
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return jwt;
}
} // namespace accless::attestation

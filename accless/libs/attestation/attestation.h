#pragma once

// Includes from Azure Guest Attestation library
#include "AttestationLogger.h"

#include <array>
#include <optional>
#include <string>
#include <vector>

namespace accless::attestation {

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

// Utility methods
class Logger : public attest::AttestationLogger {
  public:
    void Log(const char *log_tag, attest::AttestationLogger::LogLevel level,
             const char *function, const int line, const char *fmt, ...);
};

// vTPM-related methods
std::vector<uint8_t> getSnpReportFromTPM();
void tpmRenewAkCert();

// SNP-related methods
std::vector<uint8_t>
getSnpReportFromDev(std::optional<std::array<uint8_t, 64>> reportData,
                    std::optional<uint32_t> vmpl);

// Main entrypoint method to get SNP report
std::vector<uint8_t>
getSnpReport(std::optional<std::array<uint8_t, 64>> reportData);

// Attestation-service methods
std::string getAttestationServiceUrl();
std::string asGetJwtFromReport(const std::vector<uint8_t> &snpReport);
} // namespace accless::attestation

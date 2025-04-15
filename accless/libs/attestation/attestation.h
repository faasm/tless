#pragma once

// Includes from Azure Guest Attestation library
#include "AttestationLogger.h"

#include <array>
#include <optional>
#include <string>
#include <vector>

namespace accless::attestation {

constexpr size_t REPORT_BUFFER_SIZE = 4096;

struct SnpReportRequest {
    uint32_t size;
    uint32_t vmpl;
    uint8_t data[64];
    uint32_t status;
    uint8_t report[REPORT_BUFFER_SIZE];
};
typedef struct SnpReportRequest SnpReportRequest;

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

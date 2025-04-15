#pragma once

// Includes from Azure Guest Attestation library
#include "AttestationLogger.h"

#include <string>
#include <vector>

namespace accless::azure_cvm_attestation {
// Utility methods
class Logger : public attest::AttestationLogger {
  public:
    void Log(const char *log_tag, attest::AttestationLogger::LogLevel level,
             const char *function, const int line, const char *fmt, ...);
};

// vTPM-related methods
std::vector<uint8_t> getSnpReportFromTPM();
void tpmRenewAkCert();

// Attestation-service methods
std::string getAttestationServiceUrl();
std::string asGetJwtFromReport(const std::vector<uint8_t> &snpReport);
} // namespace accless::azure_cvm_attestation

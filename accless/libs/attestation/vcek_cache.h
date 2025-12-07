#pragma once

#include <mutex>
#include <string>

namespace accless::attestation::snp {

// Returns concatenated PEM (VCEK + chain) or an empty string on failure.
const std::string &getVcekPemBundle();

// If you prefer separate pieces:
const std::string &getVcekCertPem();
const std::string &getVcekChainPem();
} // namespace accless::attestation::snp

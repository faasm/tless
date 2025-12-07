#include "attestation.h"
#include "base64.h"
#include "ec_keypair.h"
#include "mock.h"

#include <array>
#include <cstdint>
#include <stdexcept>

using namespace accless::attestation::ec;

namespace accless::attestation::mock {

std::string getMockSnpAttestationJwt(const std::string &asUrl,
                                     const std::string &certPath) {
    return accless::attestation::snp::getAttestationJwt(
        asUrl, certPath, MOCK_GID, MOCK_WORKFLOW_ID, MOCK_NODE_ID);
}
} // namespace accless::attestation::mock

#pragma once

#include "attestation.h"
#include <array>
#include <string>
#include <vector>

namespace accless::attestation::mock {

const std::array<uint8_t, 8> MOCK_QUOTE_MAGIC_SNP = {'A', 'C', 'C', 'L',
                                                     'S', 'N', 'P', '!'};

const std::string MOCK_GID = "MOCKGID";
const std::string MOCK_WORKFLOW_ID = "foo";
const std::string MOCK_NODE_ID = "bar";

std::vector<uint8_t> buildMockQuote(const std::vector<uint8_t> &reportData,
                                    const std::array<uint8_t, 8> &magic);
} // namespace accless::attestation::mock

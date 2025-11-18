#include "mock.h"
#include "base64.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <memory>
#include <stdexcept>

namespace accless::attestation::mock {
constexpr size_t MOCK_QUOTE_HEADER_SIZE = 16;
constexpr uint32_t MOCK_QUOTE_VERSION = 1;

std::vector<uint8_t> buildMockQuote(const std::vector<uint8_t> &reportData,
                                    const std::array<uint8_t, 8> &magic) {
    std::vector<uint8_t> quote;
    quote.reserve(MOCK_QUOTE_HEADER_SIZE + reportData.size());

    quote.insert(quote.end(), magic.begin(), magic.end());

    uint32_t version = MOCK_QUOTE_VERSION;
    quote.push_back(static_cast<uint8_t>(version));
    quote.push_back(static_cast<uint8_t>(version >> 8));
    quote.push_back(static_cast<uint8_t>(version >> 16));
    quote.push_back(static_cast<uint8_t>(version >> 24));

    uint32_t reserved = 0;
    quote.push_back(static_cast<uint8_t>(reserved));
    quote.push_back(static_cast<uint8_t>(reserved >> 8));
    quote.push_back(static_cast<uint8_t>(reserved >> 16));
    quote.push_back(static_cast<uint8_t>(reserved >> 24));

    quote.insert(quote.end(), reportData.begin(), reportData.end());

    return quote;
}
} // namespace accless::attestation::mock

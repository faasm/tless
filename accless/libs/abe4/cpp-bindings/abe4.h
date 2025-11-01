#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

extern "C" {
void free_string(char *s);
char *setup_abe4(const char *auths_json);
} // extern "C"

namespace accless::abe4 {
struct SetupOutput {
    std::string msk;
    std::string mpk;
};

SetupOutput setup(const std::vector<std::string> &auths);

/**
 * @brief Unpacks a serialized FullKey (e.g., MPK or MSK) into a map of
 * authority to its partial key.
 *
 * This function deserializes a byte vector representing a FullKey, which is
 * essentially a collection of partial keys, each associated with an authority.
 * The FullKey is expected to be serialized in a specific format:
 * - First, a uint64_t indicating the number of partial keys.
 * - Then, for each partial key:
 *   - A uint64_t indicating the length of the authority string.
 *   - The authority string itself.
 *   - A uint64_t indicating the length of the partial key's byte
 * representation.
 *   - The partial key's byte representation.
 *
 * @param full_key_bytes A const reference to a std::string containing the
 * serialized FullKey bytes.
 * @return A std::map where keys are authority strings and values are
 * std::string representations of the partial keys (treated as black boxes).
 */
std::map<std::string, std::vector<uint8_t>>
unpackFullKey(const std::vector<uint8_t> &full_key_bytes);
} // namespace accless::abe4

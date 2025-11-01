#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

extern "C" {
void free_string(char *s);
char *setup_abe4(const char *auths_json);
char *keygen_abe4(const char *gid, const char *msk_b64,
                  const char *user_attrs_json);
} // extern "C"

namespace accless::abe4 {
struct SetupOutput {
    std::string msk;
    std::string mpk;
};

struct UserAttribute {
    std::string authority;
    std::string label;
    std::string attribute;
};

SetupOutput setup(const std::vector<std::string> &auths);

/**
 * @brief Generates a User Secret Key (USK) for a given group ID, Master Secret
 * Key (MSK), and a set of user attributes.
 *
 * This function acts as a C++ wrapper around the Rust `keygen` FFI function. It
 * takes the group ID, a base64 encoded Master Secret Key, and a vector of
 * UserAttribute objects. It serializes the user attributes to JSON, calls the
 * Rust FFI function, and returns the base64 encoded User Secret Key.
 *
 * @param gid The group ID for which the USK is to be generated.
 * @param msk A base64 encoded string representing the Master Secret Key.
 * @param user_attrs A vector of UserAttribute objects associated with the user.
 * @return A base64 encoded string representing the generated User Secret Key
 * (USK).
 */
std::string keygen(const std::string &gid, const std::string &msk,
                   const std::vector<UserAttribute> &user_attrs);

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

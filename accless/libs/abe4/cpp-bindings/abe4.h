#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

extern "C" {
void free_string(char *s);
char *setup_abe4(const char *auths_json);
char *keygen_abe4(const char *gid, const char *msk_b64,
                  const char *user_attrs_json);
char *encrypt_abe4(const char *mpk_b64, const char *policy_str);
char *decrypt_abe4(const char *usk_b64, const char *gid, const char *policy_str,
                   const char *ct_b64);

} // extern "C"

namespace accless::abe4 {
struct SetupOutput {
    std::string msk;
    std::string mpk;
};

struct EncryptOutput {
    std::string gt;
    std::string ciphertext;
};

struct UserAttribute {
    std::string authority;
    std::string label;
    std::string attribute;
};

SetupOutput setup(const std::vector<std::string> &auths);

/**
 * @brief Generates a User Secret Key (USK) for a given global ID, Master Secret
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
 * @brief Encrypts a message using the Master Public Key (MPK) and a policy.
 *
 * This function acts as a C++ wrapper around the Rust `encrypt` FFI function.
 * It takes a base64 encoded Master Public Key and a policy string. It calls the
 * Rust FFI function, and returns an `EncryptOutput` struct containing the
 * base64 encoded `Gt` and `Ciphertext`.
 *
 * @param mpk A base64 encoded string representing the Master Public Key.
 * @param policy A string representing the access policy.
 * @return An `EncryptOutput` struct containing the base64 encoded `Gt` and
 * `Ciphertext`.
 */
EncryptOutput encrypt(const std::string &mpk, const std::string &policy);

/**
 * @brief Decrypts a ciphertext using a User Secret Key (USK), group ID, policy,
 * and ciphertext.
 *
 * This function acts as a C++ wrapper around the Rust `decrypt` FFI function.
 * It takes a base64 encoded User Secret Key, group ID, policy string, and
 * base64 encoded ciphertext. It calls the Rust FFI function, and returns an
 * `std::optional<std::string>` containing the base64 encoded `Gt` if decryption
 * is successful, or `std::nullopt` otherwise.
 *
 * @param usk A base64 encoded string representing the User Secret Key.
 * @param gid The group ID associated with the decryption.
 * @param policy A string representing the access policy used for encryption.
 * @param ct A base64 encoded string representing the ciphertext to be
 * decrypted.
 * @return An `std::optional<std::string>` containing the base64 encoded `Gt` on
 * success, or `std::nullopt` on failure.
 */
std::optional<std::string> decrypt(const std::string &usk,
                                   const std::string &gid,
                                   const std::string &policy,
                                   const std::string &ct);

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

/**
 * @brief Packs a FullKey from a vector of authorities and their corresponding
 * partial keys.
 *
 * This function serializes a collection of partial keys into a single byte
 * vector representing a FullKey. The serialization format is:
 * - A uint64_t indicating the number of partial keys.
 * - For each partial key (sorted by authority):
 *   - A uint64_t for the length of the authority string.
 *   - The authority string.
 *   - A uint64_t for the length of the partial key.
 *   - The partial key bytes.
 *
 * @param authorities A const reference to a vector of authority strings.
 * @param partial_keys A const reference to a vector of partial key byte
 * vectors.
 * @return A std::vector<uint8_t> containing the serialized FullKey.
 */
std::vector<uint8_t>
packFullKey(const std::vector<std::string> &authorities,
            const std::vector<std::vector<uint8_t>> &partial_keys);

/**
 * @brief Packs a FullKey from a vector of authorities and base64-encoded
 * partial keys.
 *
 * This is an overload of packFullKey that accepts partial keys as
 * base64-encoded strings. It decodes the keys and then calls the primary
 * packFullKey function, finally returning a base64-encoded string of the packed
 * key.
 *
 * @param authorities A const reference to a vector of authority strings.
 * @param partial_keys_b64 A const reference to a vector of base64-encoded
 * partial key strings.
 * @return A std::string containing the base64-encoded serialized FullKey.
 */
std::string packFullKey(const std::vector<std::string> &authorities,
                        const std::vector<std::string> &partial_keys_b64);
} // namespace accless::abe4

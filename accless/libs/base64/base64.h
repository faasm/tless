#pragma once

#include <cstdint> // For uint8_t
#include <string>
#include <vector>

namespace accless::base64 {
/**
 * @brief Encodes a byte vector into a base64 string.
 *
 * This function takes a vector of unsigned 8-bit integers (bytes) and
 * encodes it into its base64 string representation.
 *
 * @param input A const reference to a std::vector<uint8_t> containing the
 *              binary data to be encoded.
 * @return A std::string representing the base64 encoded data.
 */
std::string encode(const std::vector<uint8_t> &input);

/**
 * @brief Decodes a base64 string into a byte vector.
 *
 * This function takes a base64 encoded string and decodes it back into
 * its original binary data representation as a vector of unsigned 8-bit
 * integers.
 *
 * @param input A const reference to a std::string containing the base64
 *              encoded data.
 * @return A std::vector<uint8_t> containing the decoded binary data.
 */
std::vector<uint8_t> decode(const std::string &input);
} // namespace accless::base64

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace accless::base64 {
/**
 * @brief Encodes a vector of bytes into a base64 string.
 *
 * @param data The vector of bytes to encode.
 * @return The base64-encoded string.
 */
std::string encode(const std::vector<uint8_t> &data);

/**
 * @brief Decodes a base64 string into a vector of bytes.
 *
 * @param data The base64-encoded string to decode.
 * @return The decoded vector of bytes.
 */
std::vector<uint8_t> decode(const std::string &data);

/**
 * @brief Encodes a vector of bytes into a URL-safe base64 string.
 *
 * This function replaces '+' with '-' and '/' with '_'.
 *
 * @param data The vector of bytes to encode.
 * @return The URL-safe base64-encoded string.
 */
std::string encodeUrlSafe(const std::vector<uint8_t> &data);

/**
 * @brief Decodes a URL-safe base64 string into a vector of bytes.
 *
 * This function replaces '-' with '+' and '_' with '/'.
 *
 * @param data The URL-safe base64-encoded string to decode.
 * @return The decoded vector of bytes.
 */
std::vector<uint8_t> decodeUrlSafe(const std::string &data);
} // namespace accless::base64

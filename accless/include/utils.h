#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace accless::utils {
std::string byteArrayToHexString(const uint8_t *data, int dataSize);

#ifdef __faasm
std::vector<uint8_t> doGetKeyBytes(const std::string &bucketName,
                                   const std::string &key,
                                   bool tolerateMissing = false);

void doAddKeyBytes(const std::string &bucketName, const std::string &key,
                   const std::string &bytes);
void doAddKeyBytes(const std::string &bucketName, const std::string &key,
                   const std::vector<uint8_t> &bytes);
#endif
} // namespace accless::utils

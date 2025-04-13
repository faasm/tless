#include "utils.h"

#ifdef __faasm
extern "C" {
#include "faasm/host_interface.h"
}
#endif
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace tless::utils {
std::string byteArrayToHexString(const uint8_t *data, int dataSize) {
    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < dataSize; ++i) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }

    return ss.str();
}

std::vector<uint8_t> base64Decode(const std::string& input) {
    const std::string base64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    auto isBase64 = [](unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    };

    std::vector<uint8_t> output;
    int val = 0;
    int valb = -8;

    for (unsigned char c : input) {
        if (!isBase64(c)) break;

        val = (val << 6) + base64Chars.find(c);
        valb += 6;

        if (valb >= 0) {
            output.push_back((uint8_t)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return output;
}

#ifdef __faasm
std::vector<uint8_t> doGetKeyBytes(const std::string &bucketName,
                                   const std::string &key,
                                   bool tolerateMissing) {
    uint8_t *ptr;
    int32_t len;
    int ret = __faasm_s3_get_key_bytes("tless", key.c_str(), &ptr, &len,
                                       tolerateMissing);

    if (len == 0 && tolerateMissing) {
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> keyBytes(len);
    std::memcpy(keyBytes.data(), ptr, len);
    std::free(ptr);

    return keyBytes;
}

void doAddKeyBytes(const std::string &bucketName, const std::string &key,
                   const std::string &bytes) {
    __faasm_s3_add_key_bytes("tless", key.c_str(), (void *)bytes.c_str(),
                             bytes.size(), true);
}

void doAddKeyBytes(const std::string &bucketName, const std::string &key,
                   const std::vector<uint8_t> &bytes) {
    __faasm_s3_add_key_bytes("tless", key.c_str(), (void *)bytes.data(),
                             bytes.size(), true);
}
#endif
} // namespace tless::utils

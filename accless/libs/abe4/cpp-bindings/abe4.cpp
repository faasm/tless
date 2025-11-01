#include "abe4.h"
#include "base64.h"

#include <cstring> // For std::memcpy
#include <nlohmann/json.hpp>

namespace accless::abe4 {

SetupOutput setup(const std::vector<std::string> &auths) {
    nlohmann::json j = auths;

    char *result = setup_abe4(j.dump().c_str());
    if (!result) {
        return {};
    }

    auto result_json = nlohmann::json::parse(result);
    free_string(result);

    return {result_json["msk"], result_json["mpk"]};
}

std::map<std::string, std::vector<uint8_t>>
unpackFullKey(const std::vector<uint8_t> &full_key_bytes) {
    std::map<std::string, std::vector<uint8_t>> result;
    const uint8_t *ptr = full_key_bytes.data();

    uint64_t num_keys;
    std::memcpy(&num_keys, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);

    for (uint64_t i = 0; i < num_keys; ++i) {
        uint64_t auth_len;
        std::memcpy(&auth_len, ptr, sizeof(uint64_t));
        ptr += sizeof(uint64_t);

        std::string auth(reinterpret_cast<const char *>(ptr), auth_len);
        ptr += auth_len;

        uint64_t key_len;
        std::memcpy(&key_len, ptr, sizeof(uint64_t));
        ptr += sizeof(uint64_t);

        std::vector<uint8_t> key(ptr, ptr + key_len);
        ptr += key_len;

        result[auth] = key;
    }

    return result;
}

} // namespace accless::abe4

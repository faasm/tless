#include "abe4.h"
#include "base64.h"

#include <cstring> // For std::memcpy
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>

namespace accless::abe4 {

SetupOutput setup(const std::vector<std::string> &auths) {
    nlohmann::json j = auths;

    char *result = setup_abe4(j.dump().c_str());
    if (!result) {
        std::cerr << "accless(abe4): FFI call to setup_abe4 failed. See Rust "
                     "logs for details."
                  << std::endl;
        throw std::runtime_error("accless(abe4): setup_abe4 FFI call failed");
    }

    auto result_json = nlohmann::json::parse(result);
    free_string(result);

    return {result_json["msk"], result_json["mpk"]};
}

SetupOutput setupPartial(const std::string &auth_id) {
    char *result = setup_partial_abe4(auth_id.c_str());
    if (!result) {
        std::cerr
            << "accless(abe4): FFI call to setup_partial_abe4 failed. See Rust "
               "logs for details."
            << std::endl;
        throw std::runtime_error(
            "accless(abe4): setup_partial_abe4 FFI call failed");
    }

    auto result_json = nlohmann::json::parse(result);
    free_string(result);

    return {result_json["msk"], result_json["mpk"]};
}

std::string keygen(const std::string &gid, const std::string &msk,
                   const std::vector<UserAttribute> &user_attrs) {
    nlohmann::json user_attrs_json = nlohmann::json::array();
    for (const auto &attr : user_attrs) {
        user_attrs_json.push_back({{"authority", attr.authority},
                                   {"label", attr.label},
                                   {"attribute", attr.attribute}});
    }

    char *result =
        keygen_abe4(gid.c_str(), msk.c_str(), user_attrs_json.dump().c_str());
    if (!result) {
        std::cerr << "accless(abe4): FFI call to keygen_abe4 failed. See Rust "
                     "logs for details."
                  << std::endl;
        throw std::runtime_error("accless(abe4): keygen_abe4 FFI call failed");
    }

    std::string usk_b64(result);
    free_string(result);

    return usk_b64;
}

std::string keygenPartial(const std::string &gid,
                          const std::string &partial_msk_b64,
                          const std::vector<UserAttribute> &user_attrs) {
    nlohmann::json user_attrs_json = nlohmann::json::array();
    for (const auto &attr : user_attrs) {
        user_attrs_json.push_back({{"authority", attr.authority},
                                   {"label", attr.label},
                                   {"attribute", attr.attribute}});
    }

    char *result = keygen_partial_abe4(gid.c_str(), partial_msk_b64.c_str(),
                                       user_attrs_json.dump().c_str());
    if (!result) {
        std::cerr << "accless(abe4): FFI call to keygen_partial_abe4 failed. "
                     "See Rust "
                     "logs for details."
                  << std::endl;
        throw std::runtime_error(
            "accless(abe4): keygen_partial_abe4 FFI call failed");
    }

    std::string partial_usk_b64(result);
    free_string(result);

    return partial_usk_b64;
}

EncryptOutput encrypt(const std::string &mpk, const std::string &policy) {
    char *result = encrypt_abe4(mpk.c_str(), policy.c_str());
    if (!result) {
        std::cerr << "accless(abe4): FFI call to encrypt_abe4 failed. See Rust "
                     "logs for details."
                  << std::endl;
        throw std::runtime_error("accless(abe4): encrypt_abe4 FFI call failed");
    }

    auto result_json = nlohmann::json::parse(result);
    free_string(result);

    return {result_json["gt"], result_json["ciphertext"]};
}

std::optional<std::string> decrypt(const std::string &usk,
                                   const std::string &gid,
                                   const std::string &policy,
                                   const std::string &ct) {
    char *result =
        decrypt_abe4(usk.c_str(), gid.c_str(), policy.c_str(), ct.c_str());
    if (!result) {
        std::cerr << "accless(abe4): FFI call to decrypt_abe4 failed. See Rust "
                     "logs for details."
                  << std::endl;
        return std::nullopt;
    }

    std::string gt_b64(result);
    free_string(result);

    return gt_b64;
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

std::vector<uint8_t>
packFullKey(const std::vector<std::string> &authorities,
            const std::vector<std::vector<uint8_t>> &partial_keys) {
    if (authorities.size() != partial_keys.size()) {
        std::cerr << "accless(abe4): packFullKey(): size mismatch between"
                  << " authorities (" << authorities.size() << ") and partial"
                  << "keys (" << partial_keys.size() << ")" << std::endl;
        throw std::runtime_error(
            "accless(abe4): size mismatch packing full key");
    }

    std::map<std::string, std::vector<uint8_t>> key_map;
    for (size_t i = 0; i < authorities.size(); ++i) {
        key_map[authorities[i]] = partial_keys[i];
    }

    std::vector<uint8_t> full_key_bytes;
    uint64_t num_keys = key_map.size();
    full_key_bytes.insert(
        full_key_bytes.end(), reinterpret_cast<const uint8_t *>(&num_keys),
        reinterpret_cast<const uint8_t *>(&num_keys) + sizeof(uint64_t));

    for (const auto &pair : key_map) {
        uint64_t auth_len = pair.first.length();
        full_key_bytes.insert(
            full_key_bytes.end(), reinterpret_cast<const uint8_t *>(&auth_len),
            reinterpret_cast<const uint8_t *>(&auth_len) + sizeof(uint64_t));
        full_key_bytes.insert(full_key_bytes.end(), pair.first.begin(),
                              pair.first.end());

        uint64_t key_len = pair.second.size();
        full_key_bytes.insert(full_key_bytes.end(),
                              reinterpret_cast<const uint8_t *>(&key_len),
                              reinterpret_cast<const uint8_t *>(&key_len) +
                                  sizeof(uint64_t)); // 4. Partial key length
        full_key_bytes.insert(full_key_bytes.end(), pair.second.begin(),
                              pair.second.end()); // 5. Partial key bytes
    }

    return full_key_bytes;
}

std::string packFullKey(const std::vector<std::string> &authorities,
                        const std::vector<std::string> &partial_keys_b64) {
    std::vector<std::vector<uint8_t>> partial_keys;
    for (const auto &key_b64 : partial_keys_b64) {
        partial_keys.push_back(accless::base64::decode(key_b64));
    }

    std::vector<uint8_t> full_key_bytes =
        packFullKey(authorities, partial_keys);
    return accless::base64::encode(full_key_bytes);
}

std::vector<std::string> getPolicyAuthorities(const std::string &policy) {
    char *result = policy_authorities_abe4(policy.c_str());
    if (!result) {
        std::cerr << "accless(abe4): FFI call to policy_authorities_abe4 "
                     "failed. See Rust "
                     "logs for details."
                  << std::endl;
        throw std::runtime_error(
            "accless(abe4): policy_authorities_abe4 FFI call failed");
    }

    auto result_json = nlohmann::json::parse(result);
    free_string(result);

    return result_json.get<std::vector<std::string>>();
}

} // namespace accless::abe4

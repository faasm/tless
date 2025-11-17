#include "ec_keypair.h"

#include <stdexcept>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

namespace accless::attestation::ec {
EcKeyPair::EcKeyPair() : key_(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) {
    if (key_ == nullptr || EC_KEY_generate_key(key_) != 1) {
        if (key_ != nullptr) {
            EC_KEY_free(key_);
        }
        throw std::runtime_error("accless(att): error generating EC key");
    }
}

EcKeyPair::~EcKeyPair() {
    if (key_ != nullptr) {
        EC_KEY_free(key_);
    }
}

EC_KEY *EcKeyPair::get() const { return key_; }

std::array<uint8_t, REPORT_DATA_SIZE> EcKeyPair::getReportData() const {
    const EC_POINT *point = EC_KEY_get0_public_key(key_);
    const EC_GROUP *group = EC_KEY_get0_group(key_);

    if (point == nullptr || group == nullptr) {
        throw std::runtime_error("accless(att): missing EC public key");
    }

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("accless(att): BN_CTX allocation failed");
    }
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (x == nullptr || y == nullptr) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        throw std::runtime_error("accless(att): BN allocation failed");
    }
    if (EC_POINT_get_affine_coordinates(group, point, x, y, ctx) != 1) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        throw std::runtime_error(
            "accless(att): failed to read EC public coordinates");
    }

    std::array<uint8_t, REPORT_DATA_SIZE / 2> gx_be{};
    std::array<uint8_t, REPORT_DATA_SIZE / 2> gy_be{};
    if (BN_bn2binpad(x, gx_be.data(), gx_be.size()) !=
            static_cast<int>(gx_be.size()) ||
        BN_bn2binpad(y, gy_be.data(), gy_be.size()) !=
            static_cast<int>(gy_be.size())) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        throw std::runtime_error(
            "accless(att): failed serialising EC coordinates");
    }

    std::array<uint8_t, REPORT_DATA_SIZE> report{};
    for (size_t i = 0; i < REPORT_DATA_SIZE / 2; i++) {
        report[i] = gx_be[REPORT_DATA_SIZE / 2 - 1 - i];
        report[REPORT_DATA_SIZE / 2 + i] =
            gy_be[REPORT_DATA_SIZE / 2 - 1 - i];
    }

    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);

    return report;
}

std::vector<uint8_t>
EcKeyPair::deriveSharedSecret(const std::vector<uint8_t> &serverPubKey) const {
    if (serverPubKey.size() != REPORT_DATA_SIZE) {
        throw std::runtime_error("accless(att): invalid server pub key size");
    }

    const EC_GROUP *group = EC_KEY_get0_group(key_);
    if (group == nullptr) {
        throw std::runtime_error("accless(att): EC group missing");
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT *point = EC_POINT_new(group);
    if (ctx == nullptr || x == nullptr || y == nullptr || point == nullptr) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        EC_POINT_free(point);
        throw std::runtime_error("accless(att): failed allocating EC helpers");
    }

    std::array<uint8_t, REPORT_DATA_SIZE / 2> gx_be{};
    std::array<uint8_t, REPORT_DATA_SIZE / 2> gy_be{};
    for (size_t i = 0; i < REPORT_DATA_SIZE / 2; i++) {
        gx_be[i] = serverPubKey[REPORT_DATA_SIZE / 2 - 1 - i];
        gy_be[i] = serverPubKey[REPORT_DATA_SIZE - 1 - i];
    }

    if (BN_bin2bn(gx_be.data(), gx_be.size(), x) == nullptr ||
        BN_bin2bn(gy_be.data(), gy_be.size(), y) == nullptr ||
        EC_POINT_set_affine_coordinates(group, point, x, y, ctx) != 1) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(y);
        EC_POINT_free(point);
        throw std::runtime_error("accless(att): failed to set peer pub key");
    }

    std::vector<uint8_t> secret(REPORT_DATA_SIZE / 2);
    int secretSize = ECDH_compute_key(secret.data(), secret.size(), point,
                                      key_, nullptr);

    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);

    if (secretSize <= 0) {
        throw std::runtime_error("accless(att): failed to derive shared key");
    }

    secret.resize(static_cast<size_t>(secretSize));
    return secret;
}
} // namespace accless::attestation::ec

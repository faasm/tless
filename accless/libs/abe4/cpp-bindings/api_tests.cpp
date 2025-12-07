#include "abe4.h"
#include "base64.h"
#include <algorithm>
#include <gtest/gtest.h>
#include <regex>
#include <set>

namespace {
std::vector<std::string>
gather_authorities(const std::vector<accless::abe4::UserAttribute> &user_attrs,
                   const std::string &policy) {
    std::set<std::string> authorities;
    for (const auto &attr : user_attrs) {
        authorities.insert(attr.authority);
    }
    for (const auto &auth : accless::abe4::getPolicyAuthorities(policy)) {
        authorities.insert(auth);
    }
    return {authorities.begin(), authorities.end()};
}
} // namespace

class Abe4ApiTest : public ::testing::Test {
  protected:
    void assert_decryption_ok(
        const std::vector<accless::abe4::UserAttribute> &user_attrs,
        const std::string &policy) {
        auto auths = gather_authorities(user_attrs, policy);
        accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);
        std::string gid = "test_gid";
        std::string usk_b64 =
            accless::abe4::keygen(gid, setup_output.msk, user_attrs);
        accless::abe4::EncryptOutput encrypt_output =
            accless::abe4::encrypt(setup_output.mpk, policy);
        std::optional<std::string> decrypted_gt = accless::abe4::decrypt(
            usk_b64, gid, policy, encrypt_output.ciphertext);

        ASSERT_TRUE(decrypted_gt.has_value());
        EXPECT_EQ(decrypted_gt.value(), encrypt_output.gt);
    }

    void assert_decryption_fail(
        const std::vector<accless::abe4::UserAttribute> &user_attrs,
        const std::string &policy) {
        auto auths = gather_authorities(user_attrs, policy);
        accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);
        std::string gid = "test_gid";
        std::string usk_b64 =
            accless::abe4::keygen(gid, setup_output.msk, user_attrs);
        accless::abe4::EncryptOutput encrypt_output =
            accless::abe4::encrypt(setup_output.mpk, policy);
        std::optional<std::string> decrypted_gt = accless::abe4::decrypt(
            usk_b64, gid, policy, encrypt_output.ciphertext);

        ASSERT_FALSE(decrypted_gt.has_value());
    }

    void assert_hybrid_round_trip(
        const std::vector<accless::abe4::UserAttribute> &user_attrs,
        const std::string &policy, const std::string &plaintext,
        const std::string &aad) {
        auto auths = gather_authorities(user_attrs, policy);
        accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);
        std::string gid = "test_gid";
        std::string usk_b64 =
            accless::abe4::keygen(gid, setup_output.msk, user_attrs);

        std::vector<uint8_t> plaintext_bytes(plaintext.begin(),
                                             plaintext.end());
        std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());

        auto hybrid_ct = accless::abe4::hybrid::encrypt(
            setup_output.mpk, policy, plaintext_bytes, aad_bytes);
        auto decrypted = accless::abe4::hybrid::decrypt(
            usk_b64, gid, policy, hybrid_ct.abe_ciphertext,
            hybrid_ct.sym_ciphertext, aad_bytes);

        ASSERT_TRUE(decrypted.has_value());
        std::string decrypted_str(decrypted->begin(), decrypted->end());
        EXPECT_EQ(plaintext, decrypted_str);
    }
};

TEST_F(Abe4ApiTest, SingleAuthSingleOk) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};
    std::string policy = "A.a:0";
    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthSingleFail) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {};
    std::string policy = "A.a:0";
    assert_decryption_fail(user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthConjunctionOk) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"},
                                                            {"A", "b", "0"}};

    std::string policy = "A.a:0 & A.b:0";

    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthConjunctionFail) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};

    std::string policy = "A.a:0 & A.b:0";

    assert_decryption_fail(user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthDisjunctionOk) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};

    std::string policy = "A.a:0 | A.a:1";

    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthDisjunctionFail) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {};

    std::string policy = "A.a:0 | A.b:0";

    assert_decryption_fail(user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthDisjunctionOk) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};

    std::string policy = "A.a:0 | B.a:0";

    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthDisjunctionFail) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"C", "a", "0"}};

    std::string policy = "A.a:0 | B.a:0";

    assert_decryption_fail(user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthConjunctionOk) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"},
                                                            {"B", "a", "0"}};

    std::string policy = "A.a:0 & B.a:0";

    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthConjunctionFail) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};

    std::string policy = "A.a:0 & B.a:0";

    assert_decryption_fail(user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthComplex1Ok) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"},
                                                            {"A", "c", "0"}};

    std::string policy = "A.a:0 | (A.b:0 & A.a:2) & (A.c:0 | A.c:1)";

    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthComplex1Fail) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "2"},
                                                            {"A", "c", "2"}};

    std::string policy = "A.a:0 | (A.b:0 & A.a:2) & (A.c:0 | A.c:1)";

    assert_decryption_fail(user_attrs, policy);
}

// FIXME (#48): flaky test only in C++, same test works fine in Rust.
TEST_F(Abe4ApiTest, DISABLED_MultiAuthComplex1Ok) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"},
                                                            {"A", "b", "2"},
                                                            {"A", "c", "1"},
                                                            {"B", "b", "0"},
                                                            {"B", "b", "1"}};

    std::string policy = "A.a:1 | (!A.a:1 & A.b:2) & !(B.b:2 | A.c:2)";

    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthComplex1Fail) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"A", "a", "2"}, {"A", "c", "1"}, {"B", "c", "2"}};

    std::string policy = "A.a:0 | (A.b:0 & A.a:2) & (A.c:1 | A.c:2)";

    assert_decryption_fail(user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiLetterAuth) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"AUTH1", "a", "0"},
        {"AUTH2", "b", "1"},
    };
    std::string policy = "AUTH1.a:0 & AUTH2.b:1";
    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, SimpleNegationOk) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"A", "c", "1"},
    };
    std::string policy = "!A.c:2";
    assert_decryption_ok(user_attrs, policy);
}

TEST_F(Abe4ApiTest, HybridRoundTripOk) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"A", "a", "0"},
        {"A", "c", "1"},
    };
    std::string policy = "A.a:0 & !A.c:0";
    std::string plaintext = "hybrid plaintext payload";
    std::string aad = "hybrid aad data";
    assert_hybrid_round_trip(user_attrs, policy, plaintext, aad);
}

TEST_F(Abe4ApiTest, HybridDecryptFailsForUnauthorizedUser) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {};
    std::string policy = "A.a:0";
    std::string plaintext = "hybrid plaintext payload";
    std::string aad = "hybrid aad data";

    auto auths = gather_authorities(user_attrs, policy);
    accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);
    std::string gid = "test_gid";
    std::string usk_b64 =
        accless::abe4::keygen(gid, setup_output.msk, user_attrs);

    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
    auto hybrid_ct = accless::abe4::hybrid::encrypt(setup_output.mpk, policy,
                                                    plaintext_bytes, aad_bytes);

    auto decrypted = accless::abe4::hybrid::decrypt(
        usk_b64, gid, policy, hybrid_ct.abe_ciphertext,
        hybrid_ct.sym_ciphertext, aad_bytes);
    ASSERT_FALSE(decrypted.has_value());
}

TEST_F(Abe4ApiTest, HybridRejectsModifiedAad) {
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};
    std::string policy = "A.a:0";
    std::string plaintext = "hybrid plaintext payload";
    std::string aad = "hybrid aad data";
    std::string wrong_aad = "tampered aad";

    auto auths = gather_authorities(user_attrs, policy);
    accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);
    std::string gid = "test_gid";
    std::string usk_b64 =
        accless::abe4::keygen(gid, setup_output.msk, user_attrs);

    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
    std::vector<uint8_t> wrong_aad_bytes(wrong_aad.begin(), wrong_aad.end());

    auto hybrid_ct = accless::abe4::hybrid::encrypt(setup_output.mpk, policy,
                                                    plaintext_bytes, aad_bytes);

    auto decrypted = accless::abe4::hybrid::decrypt(
        usk_b64, gid, policy, hybrid_ct.abe_ciphertext,
        hybrid_ct.sym_ciphertext, aad_bytes);
    ASSERT_TRUE(decrypted.has_value());
    std::string decrypted_str(decrypted->begin(), decrypted->end());
    EXPECT_EQ(plaintext, decrypted_str);

    auto tampered = accless::abe4::hybrid::decrypt(
        usk_b64, gid, policy, hybrid_ct.abe_ciphertext,
        hybrid_ct.sym_ciphertext, wrong_aad_bytes);
    ASSERT_FALSE(tampered.has_value());
}

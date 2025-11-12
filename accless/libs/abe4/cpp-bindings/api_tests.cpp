#include "abe4.h"
#include "base64.h"
#include <algorithm>
#include <gtest/gtest.h>
#include <regex>
#include <set>

class Abe4ApiTest : public ::testing::Test {
  protected:
    void assert_decryption_ok(
        std::vector<std::string> &auths,
        const std::vector<accless::abe4::UserAttribute> &user_attrs,
        const std::string &policy) {
        std::sort(auths.begin(), auths.end());

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
        std::vector<std::string> &auths,
        const std::vector<accless::abe4::UserAttribute> &user_attrs,
        const std::string &policy) {
        std::sort(auths.begin(), auths.end());

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
};

TEST_F(Abe4ApiTest, SingleAuthSingleOk) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};
    std::string policy = "A.a:0";
    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthSingleFail) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {};
    std::string policy = "A.a:0";
    assert_decryption_fail(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthConjunctionOk) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"},
                                                            {"A", "b", "0"}};

    std::string policy = "A.a:0 & A.b:0";

    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthConjunctionFail) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};

    std::string policy = "A.a:0 & A.b:0";

    assert_decryption_fail(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthDisjunctionOk) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};

    std::string policy = "A.a:0 | A.a:1";

    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthDisjunctionFail) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {};

    std::string policy = "A.a:0 | A.b:0";

    assert_decryption_fail(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthDisjunctionOk) {
    std::vector<std::string> auths = {"A", "B"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};

    std::string policy = "A.a:0 | B.a:0";

    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthDisjunctionFail) {
    std::vector<std::string> auths = {"A", "B", "C"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"C", "a", "0"}};

    std::string policy = "A.a:0 | B.a:0";

    assert_decryption_fail(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthConjunctionOk) {
    std::vector<std::string> auths = {"A", "B"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"},
                                                            {"B", "a", "0"}};

    std::string policy = "A.a:0 & B.a:0";

    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthConjunctionFail) {
    std::vector<std::string> auths = {"A", "B"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"}};

    std::string policy = "A.a:0 & B.a:0";

    assert_decryption_fail(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthComplex1Ok) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"},
                                                            {"A", "c", "0"}};

    std::string policy = "A.a:0 | (A.b:0 & A.a:2) & (A.c:0 | A.c:1)";

    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, SingleAuthComplex1Fail) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "2"},
                                                            {"A", "c", "2"}};

    std::string policy = "A.a:0 | (A.b:0 & A.a:2) & (A.c:0 | A.c:1)";

    assert_decryption_fail(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthComplex1Ok) {
    std::vector<std::string> auths = {"A", "B"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {{"A", "a", "0"},
                                                            {"A", "b", "2"},
                                                            {"A", "c", "1"},
                                                            {"B", "b", "0"},
                                                            {"B", "b", "1"}};

    std::string policy = "A.a:1 | (!A.a:1 & A.b:2) & !(B.b:2 | A.c:2)";

    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthComplex1Fail) {
    std::vector<std::string> auths = {"A", "B"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"A", "a", "2"}, {"A", "c", "1"}, {"B", "c", "2"}};

    std::string policy = "A.a:0 | (A.b:0 & A.a:2) & (A.c:1 | A.c:2)";

    assert_decryption_fail(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiLetterAuth) {
    std::vector<std::string> auths = {"AUTH1", "AUTH2"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"AUTH1", "a", "0"},
        {"AUTH2", "b", "1"},
    };
    std::string policy = "AUTH1.a:0 & AUTH2.b:1";
    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, MultiAuthComplex1OkFromCpp) {
    std::vector<std::string> auths = {"A", "B"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"A", "a", "0"},
        {"A", "b", "2"},
        {"A", "c", "1"},
        {"A", "c", "0"},
        {"B", "b", "0"},
        {"B", "b", "1"},
    };
    std::string policy = "A.a:1 | (!A.a:1 & A.b:2) & !(B.b:2 | A.c:2)";
    assert_decryption_ok(auths, user_attrs, policy);
}

TEST_F(Abe4ApiTest, SimpleNegationOk) {
    std::vector<std::string> auths = {"A"};
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"A", "c", "1"},
    };
    std::string policy = "!A.c:2";
    assert_decryption_ok(auths, user_attrs, policy);
}

#include "abe4.h"
#include "base64.h"
#include <gtest/gtest.h>
#include <regex>
#include <set>

class Abe4ApiTest : public ::testing::Test {
  protected:
    void assert_decryption_ok(
        const std::vector<accless::abe4::UserAttribute> &user_attrs,
        const std::string &policy) {
        std::vector<std::string> auths;
        std::set<std::string> auth_set;

        for (const auto &attr : user_attrs) {
            auth_set.insert(attr.authority);
        }

        std::regex re("([A-Z])\\.");
        std::sregex_iterator it(policy.begin(), policy.end(), re);
        std::sregex_iterator end;

        for (; it != end; ++it) {
            auth_set.insert((*it)[1]);
        }

        for (const auto &auth : auth_set) {
            auths.push_back(auth);
        }
        if (auths.empty()) {
            auths.push_back("A");
        }

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
        std::vector<std::string> auths;
        std::set<std::string> auth_set;

        for (const auto &attr : user_attrs) {
            auth_set.insert(attr.authority);
        }

        std::regex re("([A-Z])\\.");
        std::sregex_iterator it(policy.begin(), policy.end(), re);
        std::sregex_iterator end;

        for (; it != end; ++it) {
            auth_set.insert((*it)[1]);
        }

        for (const auto &auth : auth_set) {
            auths.push_back(auth);
        }
        if (auths.empty()) {
            auths.push_back("A");
        }

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

TEST_F(Abe4ApiTest, MultiAuthComplex1Ok) {

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

#include "abe4.h"
#include "base64.h" // New include
#include <gtest/gtest.h>

TEST(abe4, setup) {
    std::vector<std::string> auths = {"auth1", "auth2"};
    accless::abe4::setup(auths);
    SUCCEED(); // If setup doesn't throw, it's a success for now
}

TEST(Abe4Test, PartialKeyDeserialization) {
    std::vector<std::string> auths = {"auth1", "auth2"};

    accless::abe4::SetupOutput output = accless::abe4::setup(auths);
    std::vector<uint8_t> mpk_bytes =
        accless::base64::decode(output.mpk); // Changed
    std::map<std::string, std::vector<uint8_t>> mpk_map =
        accless::abe4::unpackFullKey(mpk_bytes);

    ASSERT_EQ(mpk_map.size(), 2);
    EXPECT_TRUE(mpk_map.count("auth1"));
    EXPECT_TRUE(mpk_map.count("auth2"));

    std::vector<uint8_t> msk_bytes =
        accless::base64::decode(output.msk); // Changed
    std::map<std::string, std::vector<uint8_t>> msk_map =
        accless::abe4::unpackFullKey(msk_bytes);

    ASSERT_EQ(msk_map.size(), 2);
    EXPECT_TRUE(msk_map.count("auth1"));
    EXPECT_TRUE(msk_map.count("auth2"));
}

TEST(Abe4Test, Keygen) {
    std::vector<std::string> auths = {"auth1", "auth2"};
    accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);

    std::string gid = "test_gid";
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"auth1", "label1", "attr1"}, {"auth2", "label2", "attr2"}};

    std::string usk_b64 =
        accless::abe4::keygen(gid, setup_output.msk, user_attrs);
    EXPECT_FALSE(usk_b64.empty());

    std::vector<uint8_t> usk_bytes = accless::base64::decode(usk_b64);
    std::map<std::string, std::vector<uint8_t>> usk_map =
        accless::abe4::unpackFullKey(usk_bytes);

    ASSERT_EQ(usk_map.size(), auths.size());
    for (const auto &auth : auths) {
        EXPECT_TRUE(usk_map.count(auth));
    }
}

TEST(Abe4Test, Encrypt) {
    std::vector<std::string> auths = {"auth1", "auth2"};
    accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);

    std::string policy = "auth1.label1:attr1 and auth2.label2:attr2";

    accless::abe4::EncryptOutput encrypt_output =
        accless::abe4::encrypt(setup_output.mpk, policy);
    EXPECT_FALSE(encrypt_output.gt.empty());
    EXPECT_FALSE(encrypt_output.ciphertext.empty());
}

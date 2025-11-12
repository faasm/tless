#include "abe4.h"
#include "base64.h"
#include <gtest/gtest.h>
#include <optional>

TEST(abe4, setup) {
    std::vector<std::string> auths = {"auth1", "auth2"};
    accless::abe4::setup(auths);
    SUCCEED(); // If setup doesn't throw, it's a success for now
}

TEST(Abe4Test, PartialKeyDeserialization) {
    std::vector<std::string> auths = {"auth1", "auth2"};

    accless::abe4::SetupOutput output = accless::abe4::setup(auths);
    ASSERT_FALSE(output.mpk.empty());
    ASSERT_FALSE(output.msk.empty());

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
    ASSERT_FALSE(setup_output.msk.empty());

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
    ASSERT_FALSE(setup_output.mpk.empty());

    std::string policy = "auth1.label1:attr1 and auth2.label2:attr2";

    accless::abe4::EncryptOutput encrypt_output =
        accless::abe4::encrypt(setup_output.mpk, policy);
    EXPECT_FALSE(encrypt_output.gt.empty());
    EXPECT_FALSE(encrypt_output.ciphertext.empty());
}

TEST(Abe4Test, Decrypt) {
    std::vector<std::string> auths = {"auth1", "auth2"};
    accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);
    ASSERT_FALSE(setup_output.msk.empty());
    ASSERT_FALSE(setup_output.mpk.empty());

    std::string gid = "test_gid";
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {"auth1", "label1", "attr1"}, {"auth2", "label2", "attr2"}};
    std::string usk_b64 =
        accless::abe4::keygen(gid, setup_output.msk, user_attrs);

    std::string policy = "auth1.label1:attr1 and auth2.label2:attr2";
    accless::abe4::EncryptOutput encrypt_output =
        accless::abe4::encrypt(setup_output.mpk, policy);

    std::optional<std::string> decrypted_gt =
        accless::abe4::decrypt(usk_b64, gid, policy, encrypt_output.ciphertext);
    ASSERT_TRUE(decrypted_gt.has_value());
    EXPECT_EQ(decrypted_gt.value(), encrypt_output.gt);
}

TEST(Abe4Test, PackFullKey) {
    std::vector<std::string> auths = {"auth1", "auth2"};
    accless::abe4::SetupOutput setup_output = accless::abe4::setup(auths);
    ASSERT_FALSE(setup_output.mpk.empty());

    // Unpack the original MPK
    std::vector<uint8_t> mpk_bytes = accless::base64::decode(setup_output.mpk);
    std::map<std::string, std::vector<uint8_t>> original_mpk_map =
        accless::abe4::unpackFullKey(mpk_bytes);

    // Prepare data for re-packing
    std::vector<std::string> authorities;
    std::vector<std::vector<uint8_t>> partial_keys_bytes;
    // Note: mpk_map is already sorted by key, so authorities will be sorted too.
    for (const auto &pair : original_mpk_map) {
        authorities.push_back(pair.first);
        partial_keys_bytes.push_back(pair.second);
    }

    // Re-pack the MPK
    std::vector<uint8_t> packed_mpk_bytes =
        accless::abe4::packFullKey(authorities, partial_keys_bytes);

    // Unpack the re-packed MPK
    std::map<std::string, std::vector<uint8_t>> repacked_mpk_map =
        accless::abe4::unpackFullKey(packed_mpk_bytes);

    // Compare the unpacked maps
    EXPECT_EQ(repacked_mpk_map, original_mpk_map);

    // Test with base64 strings
    std::vector<std::string> partial_keys_b64;
    for (const auto &pair : original_mpk_map) {
        partial_keys_b64.push_back(accless::base64::encode(pair.second));
    }
    std::string packed_mpk_b64 =
        accless::abe4::packFullKey(authorities, partial_keys_b64);

    // Unpack the base64 repacked MPK
    std::map<std::string, std::vector<uint8_t>> repacked_mpk_b64_map =
        accless::abe4::unpackFullKey(accless::base64::decode(packed_mpk_b64));

    // Compare the unpacked maps
    EXPECT_EQ(repacked_mpk_b64_map, original_mpk_map);
}

TEST(Abe4Test, EndToEndSingleAuthorityPartial) {
    std::string auth_id = "TEST_AUTH_ID";
    std::string gid = "test_gid";
    std::string wfId = "foo";
    std::string nodeId = "bar";

    // 1. Setup partial keys
    accless::abe4::SetupOutput partial_setup_output =
        accless::abe4::setupPartial(auth_id);
    ASSERT_FALSE(partial_setup_output.msk.empty());
    ASSERT_FALSE(partial_setup_output.mpk.empty());

    // 2. Keygen partial USK
    std::vector<accless::abe4::UserAttribute> user_attrs = {
        {auth_id, "wf", wfId}, {auth_id, "node", nodeId}};
    std::string partial_usk_b64 =
        accless::abe4::keygenPartial(gid, partial_setup_output.msk, user_attrs);
    ASSERT_FALSE(partial_usk_b64.empty());

    // 3. Pack full MPK
    std::string mpk =
        accless::abe4::packFullKey({auth_id}, {partial_setup_output.mpk});
    ASSERT_FALSE(mpk.empty());

    // 4. Pack full USK
    std::string usk = accless::abe4::packFullKey({auth_id}, {partial_usk_b64});
    ASSERT_FALSE(usk.empty());

    // 5. Define policy
    std::string policy =
        auth_id + ".wf:" + wfId + " & " + auth_id + ".node:" + nodeId;

    // 6. Encrypt
    accless::abe4::EncryptOutput encrypt_output =
        accless::abe4::encrypt(mpk, policy);
    ASSERT_FALSE(encrypt_output.gt.empty());
    ASSERT_FALSE(encrypt_output.ciphertext.empty());

    // 7. Decrypt
    std::optional<std::string> decrypted_gt =
        accless::abe4::decrypt(usk, gid, policy, encrypt_output.ciphertext);
    ASSERT_TRUE(decrypted_gt.has_value());
    EXPECT_EQ(decrypted_gt.value(), encrypt_output.gt);
}

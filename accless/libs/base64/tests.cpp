#include "base64.h"
#include <gtest/gtest.h>

TEST(Base64Test, EncodeDecodeEmpty) {
    std::vector<uint8_t> empty_input = {};
    std::string encoded = accless::base64::encode(empty_input);
    EXPECT_EQ(encoded, "");
    std::vector<uint8_t> decoded = accless::base64::decode(encoded);
    EXPECT_EQ(decoded, empty_input);
}

TEST(Base64Test, EncodeDecodeSimple) {
    std::vector<uint8_t> input = {'a', 'b', 'c'};
    std::string encoded = accless::base64::encode(input);
    EXPECT_EQ(encoded, "YWJj");
    std::vector<uint8_t> decoded = accless::base64::decode(encoded);
    EXPECT_EQ(decoded, input);
}

TEST(Base64Test, EncodeDecodePadding1) {
    std::vector<uint8_t> input = {'a', 'b', 'c', 'd'};
    std::string encoded = accless::base64::encode(input);
    EXPECT_EQ(encoded, "YWJjZA==");
    std::vector<uint8_t> decoded = accless::base64::decode(encoded);
    EXPECT_EQ(decoded, input);
}

TEST(Base64Test, EncodeDecodePadding2) {
    std::vector<uint8_t> input = {'a', 'b', 'c', 'd', 'e'};
    std::string encoded = accless::base64::encode(input);
    EXPECT_EQ(encoded, "YWJjZGU=");
    std::vector<uint8_t> decoded = accless::base64::decode(encoded);
    EXPECT_EQ(decoded, input);
}

TEST(Base64Test, EncodeDecodeLongString) {
    std::string long_str(1000, 'x');
    std::vector<uint8_t> input(long_str.begin(), long_str.end());
    std::string encoded = accless::base64::encode(input);
    std::vector<uint8_t> decoded = accless::base64::decode(encoded);
    EXPECT_EQ(decoded, input);
}

TEST(Base64UrlSafeTest, EncodeDecodeUrlSafeSimple) {
    std::vector<uint8_t> input = {'a', 'b', 'c'};
    std::string encoded = accless::base64::encodeUrlSafe(input);
    EXPECT_EQ(encoded, "YWJj");
    std::vector<uint8_t> decoded = accless::base64::decodeUrlSafe(encoded);
    EXPECT_EQ(decoded, input);
}

TEST(Base64UrlSafeTest, EncodeDecodeUrlSafeWithSpecialChars) {
    std::vector<uint8_t> input = {0xfb, 0xff, 0xbf};
    std::string encoded = accless::base64::encodeUrlSafe(input);
    EXPECT_EQ(encoded, "-__v");
    std::vector<uint8_t> decoded = accless::base64::decodeUrlSafe(encoded);
    EXPECT_EQ(decoded, input);
}

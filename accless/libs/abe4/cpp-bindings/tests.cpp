#include "abe4.h"
#include <gtest/gtest.h>

TEST(abe4, setup) {
    std::vector<std::string> auths = {"auth1", "auth2"};
    accless::abe4::setup(auths);
    SUCCEED(); // If setup doesn't throw, it's a success for now
}
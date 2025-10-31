#pragma once

#include <string>
#include <vector>

extern "C" {
void free_string(char *s);
char *setup_abe4(const char *auths_json);
} // extern "C"

namespace accless::abe4 {
struct SetupOutput {
    std::string msk;
    std::string mpk;
};

SetupOutput setup(const std::vector<std::string> &auths);
} // namespace accless::abe4

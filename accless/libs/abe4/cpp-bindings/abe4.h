#pragma once

#include <string>
#include <vector>

extern "C" {
void free_string(char *s);
char *setup_abe(const char *auths_json);
char *keygen_abe(const char *input_json);
char *encrypt_abe(const char *input_json);
char *decrypt_abe(const char *input_json);
char *iota_new(const char *gid, const char *usk);
char *tau_new(const char *policy, const char *sym_key, const char *iv);
} // extern "C"

namespace accless::abe4 {

struct SetupOutput {
    std::string msk;
    std::string mpk;
};

SetupOutput setup(const std::vector<std::string> &auths);

} // namespace accless::abe4

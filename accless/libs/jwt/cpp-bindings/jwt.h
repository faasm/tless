#pragma once

#include <string>

extern "C" {
bool verify_jwt(const char* jwt);
bool check_property(const char* jwt, const char* property, const char* exp_value);
char* get_property(const char* jwt, const char* property);
void free_string(char* ptr);
}

namespace accless::jwt {
bool verify(const std::string& jwt);
bool checkProperty(const std::string& jwt, const std::string& property, const std::string& expVal);
std::string getProperty(const std::string& jwt, const std::string& property);
}

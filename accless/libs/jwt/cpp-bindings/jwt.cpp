#include "jwt.h"

#include <iostream>
#include <string>

namespace accless::jwt {
bool verify(const std::string &jwt) { return verify_jwt(jwt.c_str()); }

bool checkProperty(const std::string &jwt, const std::string &property,
                   const std::string &expVal) {
    return check_property(jwt.c_str(), property.c_str(), expVal.c_str());
}

std::string getProperty(const std::string &jwt, const std::string &property) {
    char *result = get_property(jwt.c_str(), property.c_str());
    if (!result) {
        return "";
    }

    auto propertyOut = std::string(result);
    // Release Rust-side memory
    jwt_free_string(result);

    return propertyOut;
}
} // namespace accless::jwt

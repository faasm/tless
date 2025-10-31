#include "abe4.h"

#include <nlohmann/json.hpp>

namespace accless::abe4 {
SetupOutput setup(const std::vector<std::string> &auths) {
    nlohmann::json j = auths;

    char *result = setup_abe4(j.dump().c_str());
    if (!result) {
        return {};
    }

    auto result_json = nlohmann::json::parse(result);
    free_string(result);

    return {result_json["msk"], result_json["mpk"]};
}
} // namespace accless::abe4

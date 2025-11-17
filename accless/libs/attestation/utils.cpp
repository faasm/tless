#include "attestation.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <stdexcept>
#include <string>

namespace accless::attestation::utils {
std::string extractJsonStringField(const std::string &json,
                                   const std::string &field) {
    try {
        nlohmann::json j = nlohmann::json::parse(json);
        if (j.is_string()) {
            // If the top-level is a string, it means the actual JSON is
            // double-encoded. Parse it again.
            j = nlohmann::json::parse(j.get<std::string>());
        }
        if (j.contains(field) && j[field].is_string()) {
            return j[field].get<std::string>();
        } else {
            std::cerr << "accless(att): JSON field '" << field
                      << "' not found or not a string" << std::endl;
            throw std::runtime_error(
                "accless(att): missing or malformed JSON field " + field);
        }
    } catch (const nlohmann::json::parse_error &e) {
        std::cerr << "accless(att): JSON parse error: " << e.what()
                  << std::endl;
        throw std::runtime_error("accless(att): JSON parse error");
    } catch (const nlohmann::json::exception &e) {
        std::cerr << "accless(att): JSON error: " << e.what() << std::endl;
        throw std::runtime_error("accless(att): JSON error");
    }
}

std::string buildRequestBody(const std::string &quoteB64,
                             const std::string &runtimeB64,
                             const std::string &gid,
                             const std::string &workflowId,
                             const std::string &nodeId) {
    nlohmann::json body;
    body["draftPolicyForAttestation"] = "";
    body["nodeData"]["gid"] = gid;
    body["nodeData"]["workflowId"] = workflowId;
    body["nodeData"]["nodeId"] = nodeId;
    body["initTimeData"]["data"] = "";
    body["initTimeData"]["dataType"] = "";
    body["quote"] = quoteB64;
    body["runtimeData"]["data"] = runtimeB64;
    body["runtimeData"]["dataType"] = "Binary";
    return body.dump();
}
} // namespace accless::attestation::utils

#ifdef __faasm
#include <faasm/core.h>
#endif

#include <iostream>
#include <string>
#include <vector>

/* Driver Function - FINRA workflow
 */
int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cout << "finra(driver): usage: <s3_public_data_path> <num_audit_funcs>"
                  << std::endl;
        return 1;
    }
    std::string s3DataFile = argv[1];
    int numAuditFuncs = std::stoi(argv[2]);

    std::cout << "finra(driver): invoking one fetch-public function" << std::endl;
#ifdef __faasm
    int fetchPublicId = faasmChainNamed("fetch-public", (uint8_t*) s3DataFile.c_str(), s3DataFile.size());
#endif

    std::cout << "finra(driver): invoking one fetch-private function" << std::endl;
#ifdef __faasm
    int fetchPrivateId = faasmChainNamed("fetch-private", nullptr, 0);
#endif

    // Wait for both functions to finish
    int result = faasmAwaitCall(fetchPublicId);
    if (result != 0) {
        std::cerr << "finra(driver): error: "
                  << "fetch-public execution failed with rc: "
                  << result
                  << std::endl;
        return 1;
    }
    result = faasmAwaitCall(fetchPrivateId);
    if (result != 0) {
        std::cerr << "finra(driver): error: "
                  << "fetch-private execution failed with rc: "
                  << result
                  << std::endl;
        return 1;
    }

    std::cout << "finra(driver): invoking " << numAuditFuncs << " audit function" << std::endl;
    std::vector<int> auditFuncIds;
    int auditId;
    for (int i = 0; i < numAuditFuncs; i++) {
        std::string auditInput = std::to_string(i);
        auditInput += ":finra/outputs/fetch-public/trades";
        auditInput += ":finra/outputs/fetch-private/portfolio";
#ifdef __faasm
        int auditId = faasmChainNamed("audit", (uint8_t*) auditInput.c_str(), auditInput.size());
        auditFuncIds.push_back(auditId);
#endif
    }

    // Wait for all audit functions
    for (const auto auditId : auditFuncIds) {
#ifdef __faasm
        result = faasmAwaitCall(auditId);
        if (result != 0) {
            std::cerr << "finra(driver): error: "
                      << " audit execution (id: " << auditId << ")"
                      << std::endl
                      << "finra(driver): error: failed with rc: "
                      << result
                      << std::endl;
            return 1;
        }
#endif
    }

    std::cout << "finra(driver): invoking one merge function" << std::endl;
#ifdef __faasm
    int mergeId = faasmChainNamed("merge", nullptr, 0);
    result = faasmAwaitCall(mergeId);
    if (result != 0) {
        std::cout << "finra(driver): merge execution failed with rc "
                  << result
                  << std::endl;
        return 1;
    }
#endif

    std::string output = "finra(driver): workflow executed succesfully!";
    std::cout << output << std::endl;
#ifdef __faasm
    faasmSetOutput(output.c_str(), output.size());
#endif

    return 0;
}

#ifdef __faasm
extern "C"
{
#include "faasm/host_interface.h"
}

#include <faasm/faasm.h>
#else
#include <cstdlib>
#include <fstream>
#include <iostream>
#include "libs/s3/S3Wrapper.hpp"
#endif

#include <iostream>
#include <string>
#include <string_view>
#include <vector>

/* Merge Audit Results - FINRA workflow
 *
 * This workflow simulates loading data from a private stock holding. In this
 * case we hard-code the data in the function code.
 */
int main(int argc, char** argv)
{
    std::string bucketName = "tless";
    std::string s3prefix = "finra/outputs/audit/audit-";

#ifndef __faasm
    s3::initS3Wrapper();
    s3::S3Wrapper s3cli;
#endif

    std::cout << "finra(merge): fetching all audit results" << std::endl;
    std::vector<std::string> s3files;
#ifdef __faasm
    int numKeys = __faasm_s3_get_num_keys_with_prefix(
      bucketName.c_str(), s3prefix.c_str());

    char** keysBuffer = (char**) malloc(numKeys * sizeof(char*));
    int* keysBufferLens = (int*) malloc(numKeys * sizeof(int32_t));

    __faasm_s3_list_keys_with_prefix(
      bucketName.c_str(), s3prefix.c_str(), keysBuffer, keysBufferLens);

    for (int i = 0; i < numKeys; i++) {
        std::string tmpString;
        tmpString.assign(keysBuffer[i], keysBuffer[i] + keysBufferLens[i]);
        s3files.push_back(tmpString);
    }
#else
    s3files = s3cli.listKeys(bucketName, s3prefix);
#endif

    // For the time being, merge does nothing
    std::cout << "finra(merge): merging results from " << s3files.size() << " rules" << std::endl;
    std::string mergedAuditResults;
    for (const auto& file : s3files) {
        // First download the file
        std::string auditResults;
#ifdef __faasm
        uint8_t* keyBytes;
        int keyBytesLen;

        int ret =
          __faasm_s3_get_key_bytes(bucketName.c_str(), file.c_str(), &keyBytes, &keyBytesLen);
        if (ret != 0) {
            std::cerr << "finra(merge): error: error getting bytes from key: "
                      << file << "(bucket: " << bucketName << ")"
                      << std::endl;
            return 1;
        }
        auditResults.assign((char*) keyBytes, (char*) keyBytes + keyBytesLen);
#else
        auditResults = s3cli.getKeyStr(bucketName, file);
#endif

        // Merge does nothing
        mergedAuditResults = auditResults;
    }

    // Upload merged results
    std::string key = "finra/outputs/merge/results.txt";
    std::cout << "finra(merge): uploading merged audit results to "
              << key
              << std::endl;
#ifdef __faasm
    // Overwrite the results
    int ret =
      __faasm_s3_add_key_bytes(bucketName.c_str(),
                               key.c_str(),
                               (uint8_t*) mergedAuditResults.c_str(),
                               mergedAuditResults.size(),
                               true);
    if (ret != 0) {
        std::cerr << "finra(merge): error uploading trade data"
                  << std::endl;
        return 1;
    }
#else
    s3cli.addKeyStr(bucketName, key, mergedAuditResults);
#endif

    return 0;
}

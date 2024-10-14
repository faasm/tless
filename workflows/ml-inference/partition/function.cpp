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

std::vector<std::string> splitByDelimiter(std::string stringCopy, const std::string& delimiter)
{
    std::vector<std::string> splitString;

    size_t pos = 0;
    std::string token;
    while ((pos = stringCopy.find(delimiter)) != std::string::npos) {
        splitString.push_back(stringCopy.substr(0, pos));
        stringCopy.erase(0, pos + delimiter.length());
    }
    splitString.push_back(stringCopy);

    return splitString;
}

std::string join(const std::vector<std::string>& stringList, const std::string& delimiter)
{
    if (stringList.size() == 0) {
        return "";
    }

    std::string result = stringList.at(0);
    for (int i = 1; i < stringList.size(); i++) {
        result += delimiter;
        result += stringList.at(i);
    }

    return result;
}

/* Partition Function - ML Inference Workflow
 */
int main(int argc, char** argv)
{
    // TODO: the bucket name is currently hardcoded
    std::string bucketName = "tless";
    std::string s3dir;
    int numInfFuncs;

#ifdef __faasm
    // Get the object key as an input
    int inputSize = faasmGetInputSize();
    char inputChar[inputSize];
    faasmGetInput((uint8_t*)inputChar, inputSize);

    std::string tmpStr(inputChar, inputChar + inputSize);
    auto parts = splitByDelimiter(tmpStr, ":");
    if (parts.size() != 2) {
        std::cerr << "ml-inference(partition): error parsing driver input" << std::endl;
        return 1;
    }

    s3dir = parts.at(0);
    numInfFuncs = std::stoi(parts.at(1));
#else
    s3::initS3Wrapper();
    s3::S3Wrapper s3cli;

    // In non-WASM deployments we can get the object key as an env. variable
    char* s3dirChar = std::getenv("TLESS_S3_DIR");
    if (s3dirChar == nullptr) {
        std::cerr << "ml-inference(partition): error: must populate TLESS_S3_DIR"
                  << " env. variable!"
                  << std::endl;

        return 1;
    }
    s3dir.assign(s3dirChar);
#endif

    // Get the list of files for each PCA function
    std::cout << "ml-inference(partition): partitioning "
              << s3dir
              << " between "
              << numInfFuncs
              << " inference functions"
              << std::endl;
    std::vector<std::string> s3files(numInfFuncs);

#ifdef __faasm
    int numKeys = __faasm_s3_get_num_keys_with_prefix(
      bucketName.c_str(), s3dir.c_str());

    // In this case, we need to be careful because we have many keys, so we
    // must heap allocate both structures
    char** keysBuffer = (char**) malloc(numKeys * sizeof(char*));
    int* keysBufferLens = (int*) malloc(numKeys * sizeof(int32_t));

    __faasm_s3_list_keys_with_prefix(
      bucketName.c_str(), s3dir.c_str(), keysBuffer, keysBufferLens);

    // Pre-allocate the size of each string
    std::vector<int> sizePerInf(numInfFuncs);
    std::vector<int> numPerInf(numInfFuncs);
    for (int i = 0; i < numKeys; i++) {
        // We add 1 to account for the "," separating the file names
        sizePerInf.at(i % numInfFuncs) += keysBufferLens[i] + 1;
        numPerInf.at(i % numInfFuncs) += 1;
    }
    // Disccount one extra comma
    for (int i = 0; i < numInfFuncs; i++) {
        sizePerInf.at(i) -= 1;
    }

    // Serialize the input char** into N different char* to upload them back
    // to S3
    std::vector<char*> s3filesPtr(numInfFuncs);
    for (int i = 0; i < numInfFuncs; i++) {
        s3filesPtr.at(i) = (char*) malloc(sizePerInf.at(i));
    }

    std::vector<int> offsets(numInfFuncs);
    std::vector<int> counts(numInfFuncs);
    for (int i = 0; i < numKeys; i++) {
        int infIdx = i % numInfFuncs;
        int offset = offsets.at(infIdx);

        std::memcpy(s3filesPtr.at(infIdx) + offsets.at(infIdx), keysBuffer[i], keysBufferLens[i]);
        counts.at(infIdx) += 1;

        if (counts.at(infIdx) < numPerInf.at(infIdx)) {
            *(s3filesPtr.at(infIdx) + offset + keysBufferLens[i]) = ',';
            offsets.at(infIdx) += keysBufferLens[i] + 1;
        } else {
            offsets.at(infIdx) += keysBufferLens[i];
        }
    }
#else
    auto rawS3files = s3cli.listKeys(bucketName);
    for (int i = 0; i < rawS3files.size(); i++) {
        auto key = rawS3files.at(i);
        int funcIdx = i % numInfFuncs;

        // Filter by prefix
        if (key.rfind(s3dir, 0) == 0) {
            s3files.push_back(key);
        }
    }
#endif

    // Upload one file per calling function
    for (int i = 0; i < numInfFuncs; i++) {
        std::string key = "ml-training/outputs/partition/inf-" + std::to_string(i);
#ifdef __faasm
        // Overwrite the results
        int ret =
          __faasm_s3_add_key_bytes(bucketName.c_str(),
                                   key.c_str(),
                                   (void*) s3filesPtr.at(i),
                                   sizePerInf.at(i),
                                   true);
        if (ret != 0) {
            std::cerr << "ml-inference(partition): error uploading filenames for PCA functions" << std::endl;
            return 1;
        }
#else
        std::string fileNames = join(s3files.at(i), ",");
        s3cli.addKeyStr(bucketName, key, fileNames);
#endif
    }

    return 0;
}

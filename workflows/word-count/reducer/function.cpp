#ifdef __faasm
extern "C"
{
#include "faasm/host_interface.h"
}

#include <faasm/faasm.h>
#endif
#include <map>
#include <stdio.h>
#include <string>
#include <vector>

// TODO: Duplicated from wc_driver
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

// TODO: duplicated from wc_mapper
std::string serialiseWordCount(const std::map<std::string, int>& wordCount)
{
    std::string result;

    for (const auto& [key, val] : wordCount) {
        result += key + ":" + std::to_string(val) + ",";
    }
    result.pop_back();

    return result;
}

/* Reducer Function - Word Count Workflow
 *
 * This function takes a path to a directory as an input, reads the serialised
 * counts from each file in the directory, and then aggreagates the results
 * to one final count.
 */
int main(int argc, char** argv)
{
    // TODO: the bucket name is currently hardcoded
    std::string bucketName = "tless";
    std::string s3dir;

#ifdef __faasm
    // Get the results dir as an input
    int inputSize = faasmGetInputSize();
    char s3dirChar[inputSize];
    faasmGetInput((uint8_t*)s3dirChar, inputSize);
    s3dir.assign(s3dirChar, s3dirChar + inputSize);
#endif

    // Get the list of files in the s3 dir
    std::vector<std::string> s3files;

#ifdef __faasm
    // In Faasm we need to do a bit of work because: (i) we can not pass
    // structured objects (i.e. vectors) through the WASM calling interface,
    // and (ii) we have not implmented prefix listing, so we need to filter
    // out entries manually
    int numKeys = __faasm_s3_get_num_keys(bucketName.c_str());

    char* keysBuffer[numKeys];
    int keysBufferLens[numKeys];
    __faasm_s3_list_keys(bucketName.c_str(), keysBuffer, keysBufferLens);

    for (int i = 0; i < numKeys; i++) {
        std::string tmpString;
        tmpString.assign(keysBuffer[i], keysBuffer[i] + keysBufferLens[i]);

        // Filter by prefix
        if (tmpString.rfind(s3dir, 0) == 0) {
            s3files.push_back(tmpString);
        }
    }
#endif

    // For each output file, de-serialise results and aggreagate
    std::map<std::string, int> results;
    for (const auto& outFile : s3files) {
        // Read file contents from S3
        std::string fileContents;
#ifdef __faasm
        uint8_t* keyBytes;
        int keyBytesLen;

        int ret =
          __faasm_s3_get_key_bytes(bucketName.c_str(), outFile.c_str(), &keyBytes, &keyBytesLen);
        if (ret != 0) {
            printf("error: error getting bytes from key: %s (bucket: %s)\n",
                   outFile.c_str(),
                   bucketName.c_str());
        }

        fileContents.assign((char*) keyBytes, (char*) keyBytes + keyBytesLen);
#endif

        auto keyValPairs = splitByDelimiter(fileContents, ",");
        for (const auto& pair : keyValPairs) {
            auto splitPair = splitByDelimiter(pair, ":");
            results[splitPair.at(0)] += std::stoi(splitPair.at(1));
        }
    }

    auto resultsStr = serialiseWordCount(results);
    std::string resultKey = s3dir + "/aggregated-results.txt";
    printf("word-count(mapper): writting results to %s: %s\n", resultKey.c_str(), resultsStr.c_str());
#ifdef __faasm
    int ret =
      __faasm_s3_add_key_bytes(bucketName.c_str(),
                               resultKey.c_str(),
                               (void*) resultsStr.c_str(),
                               resultsStr.size());
#endif


    return 0;
}

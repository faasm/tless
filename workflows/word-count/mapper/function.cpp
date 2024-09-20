#ifdef __faasm
extern "C"
{
#include "faasm/host_interface.h"
}

#include <faasm/faasm.h>
#else
#include "libs/s3/S3Wrapper.hpp"
#endif

#include <map>
#include <sstream>
#include <string>

std::map<std::string, int> wordCount = {
    {"JavaScript", 0},
    {"Java", 0},
    {"PHP", 0},
    {"Python", 0},
    {"C#", 0},
    {"C++", 0},
    {"Ruby", 0},
    {"CSS", 0},
    {"Objective-C", 0},
    {"Perl", 0},
    {"Scala", 0},
    {"Haskell", 0},
    {"MATLAB", 0},
    {"Clojure", 0},
    {"Groovy", 0}
};

std::string serialiseWordCount()
{
    std::string result;

    for (const auto& [key, val] : wordCount) {
        result += key + ":" + std::to_string(val) + ",";
    }
    result.pop_back();

    return result;
}

/* Mapper Function - Step 2 of MapReduce Workflow
 *
 * The mapper function taks as an input an S3 path, and, as an output, writes
 * a serialized JSON to S3 with the partial counts of different programming
 * languages.
 */
int main(int argc, char** argv)
{
    // TODO: this is currently hardcoded
    std::string bucketName = "tless";
    std::string s3ObjectKey;

#ifdef __faasm
    // Get the object key as an input
    int inputSize = faasmGetInputSize();
    char keyName[inputSize];
    faasmGetInput((uint8_t*)keyName, inputSize);
    s3ObjectKey.assign(keyName, keyName + inputSize);
#else
    s3::initS3Wrapper();
    s3::S3Wrapper s3cli;

    // In Knative, we get the object key as an env. var
    char* s3fileChar = std::getenv("TLESS_S3_FILE");
    if (s3fileChar == nullptr) {
        std::cerr << "word-count(splitter): error: must populate TLESS_S3_FILE"
                  << " env. variable!"
                  << std::endl;

        return 1;
    }
    s3ObjectKey.assign(s3fileChar);
#endif

    // Read object from S3
    uint8_t* keyBytes;
#ifdef __faasm
    int keyBytesLen;

    int ret =
      __faasm_s3_get_key_bytes(bucketName.c_str(), s3ObjectKey.c_str(), &keyBytes, &keyBytesLen);
    if (ret != 0) {
        printf("error: error getting bytes from key: %s (bucket: %s)\n",
               s3ObjectKey.c_str(),
               bucketName.c_str());
    }
#else
    auto keyBytesVec = s3cli.getKeyBytes(bucketName, s3ObjectKey);
    keyBytes = keyBytesVec.data();
#endif

    // Read object file line-by-line, and map the inputs to our word-count map
    std::stringstream stringStream((char*) keyBytes);
    std::string currentLine;
    while (std::getline(stringStream, currentLine, '\n')) {
        for (auto& [key, val] : wordCount) {
            if (currentLine.find(key) != std::string::npos) {
                val += 1;
            }
        }
    }

    // Work-out the serialised payload and directory
    auto thisWordCount = serialiseWordCount();
    size_t lastSlash = s3ObjectKey.rfind("/");
    if (lastSlash != std::string::npos) {
        s3ObjectKey.insert(lastSlash + 1, "mapper-results/");
    } else {
        s3ObjectKey = "mapper-results/" + s3ObjectKey;
    }

    printf("word-count(mapper): writting result to %s\n", s3ObjectKey.c_str());
#ifdef __faasm
    ret =
      __faasm_s3_add_key_bytes(bucketName.c_str(),
                               s3ObjectKey.c_str(),
                               (void*) thisWordCount.c_str(),
                               thisWordCount.size());
#else
    s3cli.addKeyStr(bucketName, s3ObjectKey, thisWordCount);
    s3::shutdownS3Wrapper();
#endif

    return 0;
}

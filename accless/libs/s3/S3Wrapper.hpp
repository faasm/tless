#pragma once

#include <memory>
#include <string>
#include <vector>

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/s3/S3Client.h>

#define S3_REQUEST_TIMEOUT_MS 10000
#define S3_CONNECT_TIMEOUT_MS 500

namespace s3 {

void initS3Wrapper();

void shutdownS3Wrapper();

class S3Wrapper {
  public:
    S3Wrapper();

    void createBucket(const std::string &bucketName);

    void deleteBucket(const std::string &bucketName);

    std::vector<std::string> listBuckets();

    std::vector<std::string> listKeys(const std::string &bucketName,
                                      const std::string &prefix = "");

    void deleteKey(const std::string &bucketName, const std::string &keyName);

    void addKeyBytes(const std::string &bucketName, const std::string &keyName,
                     const std::vector<uint8_t> &data);

    void addKeyStr(const std::string &bucketName, const std::string &keyName,
                   const std::string &data);

    std::vector<uint8_t> getKeyBytes(const std::string &bucketName,
                                     const std::string &keyName,
                                     bool tolerateMissing = false);

    std::string getKeyStr(const std::string &bucketName,
                          const std::string &keyName);

  private:
    Aws::Client::ClientConfiguration clientConf;
    Aws::S3::S3Client client;
};
} // namespace s3

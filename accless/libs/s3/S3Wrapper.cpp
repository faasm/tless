#include "S3Wrapper.hpp"

#include <fmt/format.h>
#include <miniocpp/client.h>
#include <sstream>

namespace s3 {

enum class S3Error {
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    NoSuchBucket,
    NoSuchKey,
    // Used as a catch-all, ideally remove
    UnrecognisedError,
};

std::unordered_map<std::string, S3Error> errorToStringMap = {
    {"BucketAlreadyOwnedByYou", S3Error::BucketAlreadyOwnedByYou},
    {"BucketNotEmpty", S3Error::BucketNotEmpty},
    {"NoSuchBucket", S3Error::NoSuchBucket},
    {"NoSuchKey", S3Error::NoSuchKey},
};

S3Error parseError(const std::string &errorStr) {
    if (errorToStringMap.find(errorStr) == errorToStringMap.end()) {
        std::cerr << "accless(s3): unrecognised error: " << errorStr
                  << std::endl;
        return S3Error::UnrecognisedError;
    }

    return errorToStringMap.at(errorStr);
}

#define CHECK_ERRORS(response, bucketName, keyName)                            \
    {                                                                          \
        if (!response) {                                                       \
            if (std::string(bucketName).empty()) {                             \
                std::cerr << "accless(s3): general s3 error: "                 \
                          << response.code << "(" << response.message << ")"   \
                          << std::endl;                                        \
            } else if (std::string(keyName).empty()) {                         \
                std::cerr << "accless(s3): error with bucket: " << bucketName  \
                          << ": " << response.code << "(" << response.message  \
                          << ")" << std::endl;                                 \
            } else {                                                           \
                std::cerr << "accless(s3): error with bucket/key "             \
                          << bucketName << "/" << keyName << ": "              \
                          << response.code << "(" << response.message << ")"   \
                          << std::endl;                                        \
            }                                                                  \
            throw std::runtime_error("S3 error");                              \
        }                                                                      \
    };

void initS3Wrapper() {
    char *s3Host = std::getenv("S3_HOST");
    if (s3Host == nullptr) {
        std::cerr << "tless(s3): error: S3_HOST env. var not set!" << std::endl;
        throw std::runtime_error("S3 error");
    }
    std::string s3HostStr(s3Host);

    char *s3Port = std::getenv("S3_PORT");
    if (s3Port == nullptr) {
        std::cerr << "tless(s3): error: S3_PORT env. var not set!" << std::endl;
        throw std::runtime_error("S3 error");
    }
    std::string s3PortStr(s3Port);

    std::cout << "tless(s3): initialising s3 setup at " << s3HostStr << ":"
              << s3PortStr << std::endl;

    char *s3Bucket = std::getenv("S3_BUCKET");
    if (s3Bucket == nullptr) {
        std::cerr << "tless(s3): error: S3_BUCKET env. var not set!"
                  << std::endl;
        throw std::runtime_error("S3 error");
    }
    std::string s3BucketStr(s3Bucket);

    S3Wrapper s3;
    s3.createBucket(s3BucketStr);

    // Check we can write/ read
    s3.addKeyStr(s3BucketStr, "ping", "pong");
    std::string response = s3.getKeyStr(s3BucketStr, "ping");
    if (response != "pong") {
        std::cerr << "tless(s3): unable to read/write from/to S3 " << "("
                  << response << ")" << std::endl;
        throw std::runtime_error("S3 error");
    }

    std::cout << "tless(s3): succesfully pinged s3 at " << s3HostStr << ":"
              << s3PortStr << std::endl;
}

void shutdownS3Wrapper() { ; }

S3Wrapper::S3Wrapper()
    : baseUrl(minio::s3::BaseUrl(
          fmt::format("{}:{}", std::getenv("S3_HOST"), std::getenv("S3_PORT")),
          false, {})),
      provider(minio::creds::StaticProvider(std::getenv("S3_USER"),
                                            std::getenv("S3_PASSWORD"))),
      client(baseUrl, &provider) {}

void S3Wrapper::createBucket(const std::string &bucketName) {
    std::cout << "tless(s3): creating bucket " << bucketName << std::endl;
    minio::s3::MakeBucketArgs args;
    args.bucket = bucketName;
    auto response = client.MakeBucket(args);

    if (!response) {
        auto error = parseError(response.code);
        if (error == S3Error::BucketAlreadyOwnedByYou) {
            std::cout << "tless(s3): bucket already exists " << bucketName
                      << std::endl;
            return;
        }

        CHECK_ERRORS(response, bucketName, "");
    }
}

void S3Wrapper::deleteBucket(const std::string &bucketName, bool recursive) {
    std::cout << "tless(s3): deleting bucket " << bucketName << std::endl;
    minio::s3::RemoveBucketArgs args;
    args.bucket = bucketName;
    auto response = client.RemoveBucket(args);

    if (!response) {
        auto error = parseError(response.code);
        if (error == S3Error::NoSuchBucket) {
            std::cout << "tless(s3): bucket already deleted " << bucketName
                      << std::endl;
            return;
        }

        if (error == S3Error::BucketNotEmpty) {
            if (recursive) {
                std::cout << "tless(s3): error in recursive loop" << std::endl;
                throw std::runtime_error("Erroneous recurvie loop!");
            }

            std::cout << "tless(s3): bucket not empty, deleting keys "
                      << bucketName << std::endl;

            std::vector<std::string> keys = listKeys(bucketName);
            for (const auto &key : keys) {
                deleteKey(bucketName, key);
            }

            // Recursively delete
            deleteBucket(bucketName, true);
            return;
        }

        CHECK_ERRORS(response, bucketName, "");
    }
}

std::vector<std::string> S3Wrapper::listBuckets() {
    auto response = client.ListBuckets();
    CHECK_ERRORS(response, "", "");

    std::vector<std::string> bucketNames;
    for (auto const &bucketObject : response.buckets) {
        bucketNames.emplace_back(bucketObject.name);
    }

    return bucketNames;
}

std::vector<std::string> S3Wrapper::listKeys(const std::string &bucketName,
                                             const std::string &prefix) {
    minio::s3::ListObjectsArgs args;
    args.bucket = bucketName;
    if (!prefix.empty()) {
        args.prefix = prefix;
    }
    args.recursive = true;
    auto response = client.ListObjects(args);

    std::vector<std::string> keys;
    for (; response; response++) {
        minio::s3::Item item = *response;
        if (!item.name.empty()) {
            keys.push_back(item.name);
        }
    }

    return keys;
}

void S3Wrapper::deleteKey(const std::string &bucketName,
                          const std::string &keyName) {
    minio::s3::RemoveObjectArgs args;
    args.bucket = bucketName;
    args.object = keyName;

    auto response = client.RemoveObject(args);

    if (!response) {
        auto error = parseError(response.code);

        if (error == S3Error::NoSuchKey) {
            std::cout << "tless(s3): key already deleted " << bucketName << "/"
                      << keyName << std::endl;
            return;
        }

        if (error == S3Error::NoSuchBucket) {
            std::cout << "tless(s3): bucket already deleted " << bucketName
                      << "/" << keyName << std::endl;
            return;
        }

        CHECK_ERRORS(response, bucketName, keyName);
    }
}

class ByteStreamBuf : public std::streambuf {
  public:
    ByteStreamBuf(const std::vector<uint8_t> &data) {
        // Set the beginning and end of the buffer
        char *begin =
            reinterpret_cast<char *>(const_cast<uint8_t *>(data.data()));
        this->setg(begin, begin, begin + data.size());
    }
};

void S3Wrapper::addKeyBytes(const std::string &bucketName,
                            const std::string &keyName,
                            const std::vector<uint8_t> &data) {
    ByteStreamBuf buffer(data);
    std::istream iss(&buffer);

    minio::s3::PutObjectArgs args(iss, data.size(), 0);
    args.bucket = bucketName;
    args.object = keyName;

    auto response = client.PutObject(args);

    CHECK_ERRORS(response, bucketName, keyName);
}

void S3Wrapper::addKeyStr(const std::string &bucketName,
                          const std::string &keyName, const std::string &data) {
    std::istringstream iss(data);

    minio::s3::PutObjectArgs args(iss, data.size(), 0);
    args.bucket = bucketName;
    args.object = keyName;

    auto response = client.PutObject(args);

    CHECK_ERRORS(response, bucketName, keyName);
}

std::vector<uint8_t> S3Wrapper::getKeyBytes(const std::string &bucketName,
                                            const std::string &keyName,
                                            bool tolerateMissing) {
    std::vector<uint8_t> data;

    minio::s3::GetObjectArgs args;
    args.bucket = bucketName;
    args.object = keyName;

    args.datafunc = [&data](minio::http::DataFunctionArgs args) -> bool {
        data.insert(data.end(), args.datachunk.begin(), args.datachunk.end());
        return true;
    };

    auto response = client.GetObject(args);
    if (!response) {
        auto error = parseError(response.code);
        if (tolerateMissing && (error == S3Error::NoSuchKey)) {
            return std::vector<uint8_t>();
        }

        CHECK_ERRORS(response, bucketName, keyName);
    }

    return data;
}

std::string S3Wrapper::getKeyStr(const std::string &bucketName,
                                 const std::string &keyName,
                                 bool tolerateMissing) {
    std::string data;

    minio::s3::GetObjectArgs args;
    args.bucket = bucketName;
    args.object = keyName;

    args.datafunc = [&data](minio::http::DataFunctionArgs args) -> bool {
        data.append(args.datachunk);
        return true;
    };

    auto response = client.GetObject(args);
    if (!response) {
        auto error = parseError(response.code);
        if (tolerateMissing && (error == S3Error::NoSuchKey)) {
            return "";
        }

        CHECK_ERRORS(response, bucketName, keyName);
    }

    return data;
}
} // namespace s3

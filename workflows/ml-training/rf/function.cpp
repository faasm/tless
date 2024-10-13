// WARNING: this needs to preceed the OpenCV includes
// Even when threading is completely disabled, OpenCV assumes the C++ library
// has been built with threading support, and typedefs (no-ops) these two
// symbols. To prevent an undefined symbol error, we define them here.
namespace std {
    class recursive_mutex {
    public:
        void lock() {}
        bool try_lock() { return true; }
        void unlock() {}
    };

    template <typename T>
    class lock_guard {
    public:
        explicit lock_guard(T&) {}
    };
}

#ifdef __faasm
extern "C"
{
#include "faasm/host_interface.h"
}

#include <faasm/faasm.h>
#endif

#include <filesystem>
#include <iostream>
#include <opencv2/opencv.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/ml.hpp>
#include <sstream>
#include <string>
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

void loadImages(const std::string& bucketName,
                const std::string& s3file,
                std::vector<cv::Mat>& data,
                std::vector<int>& labels)
{
    std::string imageNames;
#ifdef __faasm
    uint8_t* keyBytes;
    int keyBytesLen;

    int ret =
      __faasm_s3_get_key_bytes(bucketName.c_str(), s3file.c_str(), &keyBytes, &keyBytesLen);
    if (ret != 0) {
        printf("ml-training(pca): error: error getting bytes from key: %s (bucket: %s)\n",
               s3file.c_str(),
               bucketName.c_str());
    }

    imageNames.assign((char*) keyBytes, (char*) keyBytes + keyBytesLen);
#endif

    std::istringstream ss(imageNames);
    std::string image;
    int numFiles = 0;
    while (std::getline(ss, image, ',')) {
        numFiles += 1;
    }

    ss.clear();
    ss.seekg(0, std::ios::beg);
    int label = 0;
    int progressEvery = numFiles / 5;
    while (std::getline(ss, image, ',')) {
        if ((label % progressEvery) == 0) {
            std::cout << "ml-training(pca): loaded " << label << "/" << numFiles << " images" << std::endl;
        }

        std::vector<uint8_t> imageContents;
#ifdef __faasm
        uint8_t* keyBytes;
        int keyBytesLen;

        int ret =
          __faasm_s3_get_key_bytes(bucketName.c_str(), image.c_str(), &keyBytes, &keyBytesLen);
        if (ret != 0) {
            printf("ml-training(pca): error: error getting bytes from key: %s (bucket: %s)\n",
                   image.c_str(),
                   bucketName.c_str());
        }

        imageContents.assign(keyBytes, keyBytes + keyBytesLen);
#endif

        // TODO: consider resizing instead of push_back
        cv::Mat img = cv::imdecode(imageContents, cv::IMREAD_GRAYSCALE);
        if (!img.empty()) {
            cv::resize(img, img, cv::Size(64, 64));
            data.push_back(img.reshape(1, 1));
            labels.push_back(label);
        }

        label++;
    }
}

std::vector<uint8_t> serializeMat(const cv::Mat& mat) {
    std::vector<uint8_t> buffer;

    int header[3] = { mat.rows, mat.cols, mat.type() };
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(header), reinterpret_cast<uint8_t*>(header + 3));

    size_t dataSize = mat.total() * mat.elemSize();
    const uint8_t* dataPtr = mat.ptr<uint8_t>();
    buffer.insert(buffer.end(), dataPtr, dataPtr + dataSize);

    return buffer;
}

// Function to split and serialize a Mat into N parts
std::vector<std::vector<uint8_t>> splitAndSerialize(const cv::Mat& mat, int numMats) {
    std::vector<std::vector<uint8_t>> serializedParts;
    int rowsPerPart = mat.rows / numMats;

    for (int i = 0; i < numMats; ++i) {
        int startRow = i * rowsPerPart;
        int endRow = (i == numMats - 1) ? mat.rows : (i + 1) * rowsPerPart;

        // Create a submatrix
        cv::Mat part = mat(cv::Range(startRow, endRow), cv::Range::all());
        // Serialize the submatrix
        serializedParts.push_back(serializeMat(part));
    }

    return serializedParts;
}

/*
cv::Mat deserializeMat(const std::vector<uint8_t>& buffer) {
    // Extract matrix metadata: rows, cols, type
    const int* header = reinterpret_cast<const int*>(buffer.data());
    int rows = header[0];
    int cols = header[1];
    int type = header[2];

    // Extract matrix data
    const uint8_t* dataPtr = buffer.data() + sizeof(int) * 3;
    return cv::Mat(rows, cols, type, const_cast<uint8_t*>(dataPtr)).clone();
}
*/

int main(int argc, char** argv) {
    std::string bucketName = "tless";
    std::string s3dir;
    int numTrainFuncs;

#ifdef __faasm
    // Get the object key as an input
    int inputSize = faasmGetInputSize();
    char inputChar[inputSize];
    faasmGetInput((uint8_t*)inputChar, inputSize);

    std::string tmpStr(inputChar, inputChar + inputSize);
    auto parts = splitByDelimiter(tmpStr, ":");
    if (parts.size() != 2) {
        std::cerr << "ml-training(pca): error parsing partition input" << std::endl;
        return 1;
    }

    s3dir = parts.at(0);
    numTrainFuncs = std::stoi(parts.at(1));
#endif

    std::cout << "ml-training(pca): running PCA on S3 dir "
              << s3dir
              << std::endl
              << "ml-training(pca): chaining into "
              << numTrainFuncs
              << " parallel random forest trees"
              << std::endl;

    // Load images
    std::cout << "ml-training(pca): beginning to load images..." << std::endl;
    std::vector<cv::Mat> images;
    std::vector<int> labels;
    loadImages(bucketName, s3dir, images, labels);
    std::cout << "ml-training(pca): images loaded!" << std::endl;

    // Convert data to a single matrix
    std::cout << "ml-training(pca): converting data..." << std::endl;
    cv::Mat data;
    cv::vconcat(images, data);
    data.convertTo(data, CV_32F);
    std::cout << "ml-training(pca): data converted" << std::endl;

    // Perform PCA with 10 principal components
    std::cout << "ml-training(pca): performing PCA analysis..." << std::endl;
    cv::PCA pca(data, cv::Mat(), cv::PCA::DATA_AS_ROW, 10);
    cv::Mat pcaResult;
    pca.project(data, pcaResult);

    // Prepare labels for training
    cv::Mat labelsMat(labels);
    labelsMat.convertTo(labelsMat, CV_32S);
    std::cout << "ml-training(pca): PCA on images succeded!" << std::endl;

    // Split and invoke training
    std::cout << "ml-training(pca): splitting and serializing results..." << std::endl;
    auto serializedMats = splitAndSerialize(pcaResult, numTrainFuncs);
    auto serializedLabels = serializeMat(labelsMat);
    std::cout << "ml-training(pca): splitting and serializing done!" << std::endl;

    // Upload the serialized results
    for (int i = 0; i < serializedMats.size(); i++) {
        std::string dataKey = "ml-training/outputs/pca/rf-" + std::to_string(i);
#ifdef __faasm
        // Overwrite the results
        int ret =
          __faasm_s3_add_key_bytes(bucketName.c_str(),
                                   dataKey.c_str(),
                                   serializedMats.at(i).data(),
                                   serializedMats.at(i).size(),
                                   true);
        if (ret != 0) {
            std::cerr << "ml-training(pca): error uploading PCA data for training" << std::endl;
            return 1;
        }
#else
        s3cli.addKeyStr(bucketName, dataKey, serializedMats.at(i));
#endif
    }

    // Upload the labels
    std::string labelsKey = "ml-training/outputs/pca/labels";
#ifdef __faasm
    // Overwrite the results
    int ret =
      __faasm_s3_add_key_bytes(bucketName.c_str(),
                               labelsKey.c_str(),
                               serializedLabels.data(),
                               serializedLabels.size(),
                               true);
    if (ret != 0) {
        std::cerr << "ml-training(pca): error uploading labels data for training" << std::endl;
        return 1;
    }
#else
    s3cli.addKeyStr(bucketName, labelsKey, serializedLabels.at(i));
#endif

    std::vector<std::string> trainFuncIds;
    for (int i = 0; i < numTrainFuncs; i++) {
        std::string dataKey = "ml-training/outputs/pca/rf-" + std::to_string(i);
        std::string pcaInput = dataKey + ":" + labelsKey;
#ifdef __faasm
        int pcaId = faasmChainNamed("rf", (uint8_t*) pcaInput.c_str(), pcaInput.size());
#endif
        trainFuncIds.push_back(std::to_string(pcaId));
    }

    // Tell the driver the ids of the PCA funcs to wait on them
#ifdef __faasm
    std::string outputStr = join(trainFuncIds, ",");
    faasmSetOutput(outputStr.c_str(), outputStr.size());
#endif

    /*
    // Train k-NN classifier with PCA result
    cv::Ptr<cv::ml::KNearest> knn = cv::ml::KNearest::create();
    knn->setDefaultK(3);
    knn->train(pcaResult, cv::ml::ROW_SAMPLE, labelsMat);
    std::cout << "Training k-NN classifier succeeded!" << std::endl;

    // Perform a prediction on the first sample as an example
    cv::Mat sample = pcaResult.row(0);
    cv::Mat response;
    knn->findNearest(sample, knn->getDefaultK(), response);
    std::cout << "Predicted label: " << response.at<float>(0, 0) << std::endl;
    */

    return 0;
}

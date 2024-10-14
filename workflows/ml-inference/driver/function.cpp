#ifdef __faasm
#include <faasm/core.h>
#endif

#include <iostream>
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

/* Driver Function - ML inference workflow
 *
 * This function acts as a "coordinator" for the ML training workflow. It
 * reduces the amount of workflow-specific logic that we need to implement in
 * Faasm.
 *
 * As an input, this workflow gets the S3 path to read model data from, the S3
 * path to load the images from and the number of inference functions to run.
 */
int main(int argc, char** argv)
{
    if (argc != 4) {
        std::cout << "ml-infernce(driver): usage: <s3_path_model> <s3_image_data> <num_inf_funcs>"
                  << std::endl;
        return 1;
    }
    std::string s3ModelPrefix = argv[1];
    std::string s3DataPrefix = argv[2];
    int numInfFuncs = std::stoi(argv[3]);

    // Invoke one instance of the partition function. It will populate
    // different files in S3 with the images to run inference on for each
    // inference function
    std::cout << "ml-inference(driver): invoking one partition function" << std::endl;
#ifdef __faasm
    std::string partitionInput = s3DataPrefix + ":" + std::to_string(numInfFuncs);
    int partitionId = faasmChainNamed("partition", (uint8_t*) partitionInput.c_str(), partitionInput.size());
#endif

    // Invoke one instance of the model loading function
    std::cout << "ml-inference(driver): invoking one load function" << std::endl;
#ifdef __faasm
    std::string loadInput = s3ModelPrefix;
    int loadId = faasmChainNamed("load", (uint8_t*) loadInput.c_str(), loadInput.size());
#endif

    // Wait for both partition and load to finish
    int result = faasmAwaitCall(partitionId);
    if (result != 0) {
        std::cerr << "ml-inference(driver): error: "
                  << "partition execution failed with rc: "
                  << result
                  << std::endl;
        return 1;
    }
    result = faasmAwaitCall(loadId);
    if (result != 0) {
        std::cerr << "ml-inference(driver): error: "
                  << "load execution failed with rc: "
                  << result
                  << std::endl;
        return 1;
    }

    // Wait for all PCA functions to have finished
    std::cout << "ml-inference(driver): invoking " << numInfFuncs
              << " inference functions..."
              << std::endl;
    std::vector<int> inferenceIds(numInfFuncs);
    std::string loadOutput = "ml-inference/outputs/load";
    std::string partitionOutput = "ml-inferene/outputs/partition/inf-";
    for (int i = 0; i < numInfFuncs; i++) {
        std::string infInput = std::to_string(i) + ":" + loadOutput + ":" + partitionOutput + std::to_string(i);
        int infId = faasmChainNamed("predict", (uint8_t*) infInput.c_str(), infInput.size());
        inferenceIds.at(i) = infId;
    }

    for (auto infId : inferenceIds) {
#ifdef __faasm
        result = faasmAwaitCall(infId);
        if (result != 0) {
            std::cerr << "ml-inference(driver): error: "
                      << " inference execution (id: " << infId << ")"
                      << std::endl
                      << "ml-infernce(driver): error: failed with rc: "
                      << result
                      << std::endl;
            return 1;
        }
#endif
    }

    std::string output = "ml-inference(driver): workflow executed succesfully!";
    std::cout << output << std::endl;
#ifdef __faasm
    faasmSetOutput(output.c_str(), output.size());
#endif

    return 0;
}

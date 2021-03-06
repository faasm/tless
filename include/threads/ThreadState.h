#pragma once

#include <memory>
#include <mutex>
#include <vector>

#include <faabric/proto/faabric.pb.h>
#include <faabric/util/environment.h>
#include <faabric/util/locks.h>

namespace threads {

// A Level is a layer of threads in an OpenMP application.
// Note, defaults are set to replicate the behaviour as of Clang 9.0.1
class Level
{
  public:
    // Number of nested OpenMP constructs
    int32_t depth = 0;

    // Number of parallel regions with more than 1 thread above this level
    int32_t activeLevels = 0;

    // Max number of active parallel regions allowed
    int32_t maxActiveLevels = 1;

    // Number of threads of this level
    int32_t numThreads = 1;

    // Desired number of thread set by omp_set_num_threads for all future levels
    int32_t wantedThreads = -1;

    // Num threads pushed by compiler, valid for one parallel section.
    // Overrides wantedThreads
    int32_t pushedThreads = -1;

    // Offset for the global thread numbers at this level
    int32_t globalTidOffset = 0;

    uint32_t nSharedVarOffsets = 0;
    std::unique_ptr<uint32_t[]> sharedVarOffsets;
    static_assert(sizeof(sharedVarOffsets) == sizeof(uint32_t*));

    static std::shared_ptr<Level> deserialise(
      const std::vector<uint8_t>& bytes);

    Level(int32_t numThreadsIn);

    std::vector<uint32_t> getSharedVarOffsets();

    void setSharedVarOffsets(uint32_t* ptr, int nVars);

    void fromParentLevel(const std::shared_ptr<Level>& parent);

    // Instance functions
    int getMaxThreadsAtNextLevel() const;

    std::vector<uint8_t> serialise();

    int getLocalThreadNum(const faabric::Message* msg);

    int getGlobalThreadNum(int localThreadNum);

    int getGlobalThreadNum(const faabric::Message* msg);

    std::string toString();
};

class PthreadCall
{
  public:
    int32_t pthreadPtr;
    int32_t entryFunc;
    int32_t argsPtr;
};

std::shared_ptr<Level> levelFromBatchRequest(
  const std::shared_ptr<faabric::BatchExecuteRequest>& req);

std::shared_ptr<Level> getCurrentOpenMPLevel();

void setCurrentOpenMPLevel(
  const std::shared_ptr<faabric::BatchExecuteRequest> req);

void setCurrentOpenMPLevel(const std::shared_ptr<Level>& level);
}

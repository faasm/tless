#pragma once

#include <AttestationClient.h>

#include <chrono>

class Logger : public attest::AttestationLogger {
  public:
    void Log(const char *log_tag, LogLevel level, const char *function,
             const int line, const char *fmt, ...);
};

std::chrono::duration<double>
runMaaRequests(int numRequests, int maxParallelism, const std::string &maaUrl);

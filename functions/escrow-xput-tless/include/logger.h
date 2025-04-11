#pragma once

#include <AttestationClient.h>

class Logger : public attest::AttestationLogger {
public:
  void Log(const char *log_tag, LogLevel level, const char *function,
           const int line, const char *fmt, ...);
};

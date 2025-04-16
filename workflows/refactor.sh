#!/bin/bash

# Directory to operate on (default is current)
TARGET_DIR=${1:-.}

# Find all relevant files (e.g., .cpp, .h, .hpp, etc.)
find "$TARGET_DIR" -type f \( -name '*.cpp' -o -name '*.h' -o -name '*.hpp' -o -name '*.cc' \) | while read -r file; do
  echo "Processing $file"

  sed -i \
    -e 's|#include "libs/s3/S3Wrapper.h"|#include "s3/S3Wrapper.h"|' \
    -e 's|#include "tless.h"|#include "accless.h"|' \
    -e 's|\btless::checkChain\b|accless::checkChain|g' \
    "$file"
done

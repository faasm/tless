#!/bin/bash

# Copyright(c) The Maintainers of Nanvix.
# Licensed under the MIT License.

#
# Utility functions.
#

#===================================================================================================
# Include Guard
#===================================================================================================

# Skip this file if already included.
if [[ -n "${__UTILS_SH_INCLUDED:-}" ]]; then
    return
fi
readonly __UTILS_SH_INCLUDED=1

#==================================================================================================
# Imports
#==================================================================================================

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

#==================================================================================================
# Functions
#==================================================================================================

#
# Checks if the --clean flag was passed.
# Returns 0 (true) if the flag is present, 1 (false) otherwise.
#
has_clean_flag() {
    for arg in "$@"; do
        if [[ "$arg" == "--clean" ]]; then
            return 0 # 0 means "true" (success)
        fi
    done
    return 1 # 1 means "false" (failure)
}

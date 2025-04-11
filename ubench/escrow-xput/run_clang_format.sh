#!/bin/bash

find . -regex '.*\.\(cpp\|hpp\|cc\|c\|h\)' -exec clang-format -i {} \;

#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."
WORKFLOW_BUILD_DIR=${PROJ_ROOT}/workflows/build-wasm/$1

pushd ${PROJ_ROOT} >> /dev/null

for file in "${WORKFLOW_BUILD_DIR}"/*.wasm;
do
    if [[ -f $file ]]; then
        filename=$(basename "$file")
        # Extract the word between the underscore and the dot
        function=$(echo "$filename" | sed -E 's/.*_(.*)\..*/\1/')
        faasmctl upload $1 $function ${WORKFLOW_BUILD_DIR}/$filename
    fi
done

popd >> /dev/null

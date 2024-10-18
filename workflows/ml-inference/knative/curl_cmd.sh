#!/bin/bash

THIS_RUN_MAGIC=${RANDOM}

# ${COCO_SOURCE:-/usr/local}/bin/kubectl run curl --image=curlimages/curl --rm=true --restart=Never -ti -- -X POST -v \
#    -H "content-type: application/json"  \
#    -H "ce-specversion: 1.0" \
#    -H "ce-source: cli" \
#    -H "ce-type: http://partition-to-pca-kn-channel.tless.svc.cluster.local" \
#    -H "ce-id: 1" \
#    -d '{"data-dir": "ml-training/mnist-images-2k", "num-pca-funcs": 2, "num-train-funcs": 8, "run-magic": '"${THIS_RUN_MAGIC}}"'' \
#    http://ingress-to-partition-kn-channel.tless.svc.cluster.local

curl -X POST -v \
   -H "content-type: application/json"  \
   -H "ce-specversion: 1.0" \
   -H "ce-type: http://all-to-inference-kn-channel.tless.svc.cluster.local" \
   -H "ce-id: 1" \
   -H "ce-source: pre-inf" \
   -d '{"inf-id": 0, "model-dir": "ml-inference/model", "data-dir": "ml-inference/images-inference-1k", "num-inf-funcs": 12, "run-magic": '"${THIS_RUN_MAGIC}}"'' \
   http://localhost:8080

# Change this to test partition

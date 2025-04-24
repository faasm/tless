#!/bin/bash

THIS_RUN_MAGIC=${RANDOM}
# Support overriding for scale-up plots
NUM_INF_FUNCS=${OVERRIDE_NUM_INF_FUNCS:-8}

${COCO_SOURCE:-/usr/local}/bin/kubectl run curl-${THIS_RUN_MAGIC} --image=curlimages/curl --rm=true --restart=Never -i -- -X POST -v \
   -H "content-type: application/json"  \
   -H "ce-specversion: 1.0" \
   -H "ce-source: cli-partition" \
   -H "ce-type: http://pre-inf-to-predict-kn-channel.accless.svc.cluster.local" \
   -H "ce-id: 1" \
   -d '{"model-dir": "ml-inference/model", "data-dir": "ml-inference/images-inference-1k", "num-inf-funcs": '"${NUM_INF_FUNCS}"', "run-magic": '"${THIS_RUN_MAGIC}}"'' \
   http://ingress-to-partition-kn-channel.accless.svc.cluster.local &

${COCO_SOURCE:-/usr/local}/bin/kubectl run curl2-${THIS_RUN_MAGIC} --image=curlimages/curl --rm=true --restart=Never -i -- -X POST -v \
   -H "content-type: application/json"  \
   -H "ce-specversion: 1.0" \
   -H "ce-source: cli-load" \
   -H "ce-type: http://pre-inf-to-predict-kn-channel.accless.svc.cluster.local" \
   -H "ce-id: 1" \
   -d '{"model-dir": "ml-inference/model", "data-dir": "ml-inference/images-inference-1k", "num-inf-funcs": '"${NUM_INF_FUNCS}"', "run-magic": '"${THIS_RUN_MAGIC}}"'' \
   http://ingress-to-load-kn-channel.accless.svc.cluster.local

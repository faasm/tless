#!/bin/bash

THIS_RUN_MAGIC=${RANDOM}
# Support overriding for scale-up plots
NUM_AUDIT_FUNCS=${OVERRIDE_NUM_AUDIT_FUNCS:-8}

${COCO_SOURCE:-/usr/local}/bin/kubectl run curl-${THIS_RUN_MAGIC} --image=curlimages/curl --rm=true --restart=Never -i -- -X POST -v \
   -H "content-type: application/json"  \
   -H "ce-specversion: 1.0" \
   -H "ce-source: cli-fetch-public" \
   -H "ce-type: http://fetch-to-audit-kn-channel.accless.svc.cluster.local" \
   -H "ce-id: 1" \
   -d '{"num-audit": '"${NUM_AUDIT_FUNCS}"', "run-magic": '"${THIS_RUN_MAGIC}"'}' \
   http://ingress-to-fetch-public-kn-channel.accless.svc.cluster.local &

sleep 1

${COCO_SOURCE:-/usr/local}/bin/kubectl run curl-2-${THIS_RUN_MAGIC} --image=curlimages/curl --rm=true --restart=Never -i -- -X POST -v \
   -H "content-type: application/json"  \
   -H "ce-specversion: 1.0" \
   -H "ce-source: cli-fetch-private" \
   -H "ce-type: http://fetch-to-audit-kn-channel.accless.svc.cluster.local" \
   -H "ce-id: 1" \
   -d '{"num-audit": '"${NUM_AUDIT_FUNCS}"', "run-magic": '"${THIS_RUN_MAGIC}"'}' \
   http://ingress-to-fetch-private-kn-channel.accless.svc.cluster.local

# curl -X POST -v \
#    -H "content-type: application/json"  \
#    -H "ce-specversion: 1.0" \
#    -H "ce-source: audit" \
#    -H "ce-type: http://fetch-to-audit-kn-channel.tless.svc.cluster.local" \
#    -H "ce-id: 1" \
#    -d '{"num-audit": 2, "audit-id": 0, "run-magic": '"${THIS_RUN_MAGIC}}"'' \
#    http://localhost:8080

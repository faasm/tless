#!/bin/bash

THIS_RUN_MAGIC=${RANDOM}

${COCO_SOURCE:-/usr/local}/bin/kubectl run curl-${THIS_RUN_MAGIC} --image=curlimages/curl --rm=true --restart=Never -i -- -X POST -v \
   -H "content-type: application/json"  \
   -H "ce-specversion: 1.0" \
   -H "ce-source: cli" \
   -H "ce-type: http://splitter-to-mapper-kn-channel.accless.svc.cluster.local" \
   -H "ce-id: 1" \
   -d '{"foo":"bar"}' \
   http://ingress-to-splitter-kn-channel.accless.svc.cluster.local

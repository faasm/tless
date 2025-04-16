#!/bin/bash

${COCO_SOURCE:-/usr/local}/bin/kubectl \
    run curl --image=curlimages/curl \
    --rm=true --restart=Never -i -- -X GET \
    http://cold-start.accless.svc.cluster.local

#/bin/bash

docker run \
    --rm -it -d \
    --net host \
    --name minio-test \
    --env MINIO_ROOT_USER=minio \
    --env MINIO_ROOT_PASSWORD=minio123 \
    minio/minio:RELEASE.2024-09-13T20-26-02Z server /data/minio

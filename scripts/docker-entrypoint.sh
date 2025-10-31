#!/bin/bash
set -e

USER_ID=${HOST_UID:-9001}
GROUP_ID=${HOST_GID:-9001}

groupadd -g $GROUP_ID accless
useradd -u $USER_ID -g $GROUP_ID -s /bin/bash accless

export HOME=/home/accless
chown -R accless:accless /home/accless

exec /usr/sbin/gosu accless "$@"

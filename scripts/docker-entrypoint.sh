#!/bin/bash
set -e

USER_ID=${HOST_UID:-9001}
GROUP_ID=${HOST_GID:-9001}

groupadd -g $GROUP_ID accless
useradd -u $USER_ID -g $GROUP_ID -s /bin/bash -K UID_MAX=200000 accless
usermod -aG sudo accless
echo "accless ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/accless

export HOME=/home/accless
mkdir -p ${HOME}
cp -r /root/.cargo ${HOME}/.cargo
cp -r /root/.rustup ${HOME}/.rustup
chown -R accless:accless /code
chown -R accless:accless ${HOME}

echo ". /code/accless/scripts/workon.sh" >> ${HOME}/.bashrc
echo ". ${HOME}/.cargo/env" >> ${HOME}/.bashrc

exec /usr/sbin/gosu accless bash -lc \
  'source /code/accless/scripts/workon.sh; source "$HOME/.cargo/env"; exec "$@"' \
  bash "$@"

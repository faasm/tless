#!/bin/bash

set -e

USER_ID=${HOST_UID:-9001}
GROUP_ID=${HOST_GID:-9001}

# Group ID that owns /dev/sev-guest for SNP deployments (if present).
SEV_GID=${SEV_GID:-}

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

# Add /dev/sev-guest owning group if necessary.
if [ -e /dev/sev-guest ]; then
    if [ -n "$SEV_GID" ]; then
        # Create a group with that GID if needed (name "sevguest" or whatever)
        if ! getent group "$SEV_GID" >/dev/null; then
            groupadd -g "$SEV_GID" sevguest || true
        fi

        # Add accless to that group (by GID to be robust to name differences)
        usermod -aG "$SEV_GID" accless || true
    else
        echo "WARNING: /dev/sev-guest present but SEV_GID not set!"
    fi
fi

exec /usr/sbin/gosu accless bash -lc \
  'source /code/accless/scripts/workon.sh; source "$HOME/.cargo/env"; exec "$@"' \
  bash "$@"

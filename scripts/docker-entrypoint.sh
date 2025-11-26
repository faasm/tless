#!/bin/bash

set -e

USER_ID=${HOST_UID:-9001}
GROUP_ID=${HOST_GID:-9001}
USER_NAME=accless

# Group ID that owns /dev/sev-guest for SNP deployments (if present).
SEV_GID=${SEV_GID:-}

# Create group if it doesn't exist
if ! getent group "$GROUP_ID" >/dev/null 2>&1; then
    groupadd -g "$GROUP_ID" "$USER_NAME"
fi

# Create user if it doesn't exist
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    useradd -u "$USER_ID" -g "$GROUP_ID" -s /bin/bash -K UID_MAX=200000 -m "$USER_NAME"
    usermod -aG sudo ${USER_NAME}
    echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USER_NAME
fi

export HOME=/home/${USER_NAME}
mkdir -p ${HOME}

# Add user to group that owns the rust toolchain.
if getent group rusttool >/dev/null 2>&1; then
    usermod -aG rusttool "$USER_NAME"
fi

[ ! -e "$HOME/.cargo" ]  && ln -s /opt/rust/cargo   "$HOME/.cargo"
[ ! -e "$HOME/.rustup" ] && ln -s /opt/rust/rustup "$HOME/.rustup"

# Add /dev/sev-guest owning group if necessary.
if [ -e /dev/sev-guest ]; then
    if [ -n "$SEV_GID" ]; then
        # Create a group with that GID if needed (name "sevguest" or whatever)
        if ! getent group "$SEV_GID" >/dev/null; then
            groupadd -g "$SEV_GID" sevguest || true
        fi

        # Add accless to that group (by GID to be robust to name differences)
        usermod -aG "$SEV_GID" ${USER_NAME} || true
    else
        echo "WARNING: /dev/sev-guest present but SEV_GID not set!"
    fi
fi

exec /usr/sbin/gosu ${USER_NAME} bash -c \
  'source /code/accless/scripts/workon.sh; source "$HOME/.cargo/env"; exec "$@"' \
  bash "$@"

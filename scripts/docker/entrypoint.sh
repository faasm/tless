#!/bin/bash

set -e

USER_ID=${HOST_UID:-9001}
GROUP_ID=${HOST_GID:-9001}
USER_NAME=accless

# Group ID that owns /dev/sev-guest for bare-metal SNP deployments (if present).
SEV_GID=${SEV_GID:-}

# Group ID that owns /dev/tpmrm0 for SNP deployments on Azure (if present).
TPM_GID=${TPM_GID:-}

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

# Add user to group that owns the faasm toolchain.
if getent group faasm >/dev/null 2>&1; then
    usermod -aG faasm "$USER_NAME"
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

# Add /dev/tpmrm0 owning group if necessary.
if [ -e /dev/tpmrm0 ]; then
    if [ -n "$TPM_GID" ]; then
        # Create a group with that GID if needed.
        if ! getent group "$TPM_GID" >/dev/null; then
            groupadd -g "$TPM_GID" tssctr || true
        fi

        # Add accless to that group (by GID to be robust to name differences)
        usermod -aG "${TPM_GID}" ${USER_NAME} || true
    else
        echo "WARNING: /dev/tpmrm0 present but TPM_GID not set!"
    fi
fi

echo ". /code/accless/scripts/workon.sh" >> ${HOME}/.bashrc
echo ". ${HOME}/.cargo/env" >> ${HOME}/.bashrc

exec /usr/sbin/gosu "$USER_NAME" bash -c \
  'source /code/accless/scripts/workon.sh 2>/dev/null || true; \
   source "$HOME/.cargo/env" 2>/dev/null || true; \
   exec "$@"' \
  bash "$@"

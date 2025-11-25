#!/bin/bash

set -euo pipefail

THIS_DIR="$(dirname "$(realpath "$0")")"
SCRIPTS_DIR="${THIS_DIR}/.."
ROOT_DIR="${SCRIPTS_DIR}/.."
OUTPUT_DIR="${THIS_DIR}/output"

source "${SCRIPTS_DIR}/common/utils.sh"
source "${THIS_DIR}/versions.sh"

clean() {
    print_info "Cleaning and re-creating ${OUTPUT_DIR} directory..."
    rm -rf ${OUTPUT_DIR}
    mkdir -p ${OUTPUT_DIR}
}

# TODO: check host kernel

#
# Fetch the linux kernel image.
#
install_apt_deps() {
    print_info "Installing APT dependencies..."
    sudo apt install -y cloud-utils ovmf > /dev/null 2>&1
}

#
# Build up-to-date QEMU (need >= 9.x).
#
build_qemu() {
    print_info "Building and installing QEMU (v${QEMU_VERSION}) from source (will take a minute)..."
    local qemu_out_dir="${OUTPUT_DIR}/qemu"
    mkdir -p ${qemu_out_dir}
    pushd ${qemu_out_dir} >> /dev/null

    wget https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz > /dev/null 2>&1
    tar xvJf qemu-${QEMU_VERSION}.tar.xz > /dev/null 2>&1
    pushd qemu-${QEMU_VERSION} >> /dev/null
    ./configure --enable-slirp > /dev/null 2>&1
    make -j $(nproc) > /dev/null 2>&1
    popd >> /dev/null

    popd >> /dev/null
    print_success "Successfully built QEMU (v${QEMU_VERSION})!"
}

#
# Build up-to-date OVMF version.
#
build_ovmf() {
    print_info "Building and installing OVMF (${OVMF_VERSION}) from source..."
    local ovmf_out_dir="${OUTPUT_DIR}/ovmf"
    mkdir -p ${ovmf_out_dir}
    pushd ${ovmf_out_dir} >> /dev/null

    if [ ! -d "ovmf-${OVMF_VERSION}" ]; then
        git clone -b ${OVMF_VERSION} https://github.com/tianocore/edk2.git ovmf-${OVMF_VERSION} > /dev/null 2>&1
    fi

    pushd ovmf-${OVMF_VERSION} >> /dev/null
    git submodule update --init --recursive > /dev/null 2>&1
    make -C BaseTools clean > /dev/null 2>&1
    make -C BaseTools -j $(nproc) > /dev/null 2>&1
    . ./edksetup.sh --reconfig
    build -a X64 -b RELEASE -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc > /dev/null 2>&1
    touch  OvmfPkg/AmdSev/Grub/grub.efi > /dev/null 2>&1
    build -a X64 -b RELEASE -t GCC5 -p OvmfPkg/AmdSev/AmdSevX64.dsc > /dev/null 2>&1
    popd >> /dev/null

    popd >> /dev/null
    print_success "Successfully built OVMF (${OVMF_VERSION})!"
}

#
# Fetch the linux kernel image.
#
fetch_kernel() {
    print_info "Fetching Linux kernel..."
    wget \
        https://cloud-images.ubuntu.com/noble/${UBUNTU_VERSION}/unpacked/noble-server-cloudimg-amd64-vmlinuz-generic \
        -O ${OUTPUT_DIR}/vmlinuz-noble > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "Linux kernel fetched successfully."
    else
        print_error "Failed to fetch Linux kernel."
        exit 1
    fi

    print_info "Fetching initrd..."
    wget \
        https://cloud-images.ubuntu.com/noble/${UBUNTU_VERSION}/unpacked/noble-server-cloudimg-amd64-initrd-generic \
        -O ${OUTPUT_DIR}/initrd-noble > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "Kernel initrd fetched successfully."
    else
        print_error "Failed to fetch kernel initrd."
        exit 1
    fi
}

#
# Provision the disk image.
#
provision_disk_image() {
    local disk_img="${OUTPUT_DIR}/disk.img"
    print_info "Provisioning disk image (path=${disk_img})..."

    local root_mnt="/mnt/cvm-root"
    local qemu_nbd="${OUTPUT_DIR}/qemu/qemu-${QEMU_VERSION}/build/qemu-nbd"

    # Attach to disk image.
    sudo modprobe nbd max_part=8
    sudo ${qemu_nbd} --connect=/dev/nbd0 "${disk_img}"
    sudo partprobe /dev/nbd0 2>/dev/null || true

    # Fix GPT metadata after qemu-img resize.
    sudo sgdisk -e /dev/nbd0

    disk_provision_cleanup() {
        local root_mnt=$1
        local qemu_nbd=$2
        echo "[provision-disk] Cleaning up..."
        set +e
        sudo umount -R "${root_mnt}" > /dev/null 2>&1 || true
        sudo ${qemu_nbd} --disconnect /dev/nbd0 > /dev/null 2>&1 || true
        sudo rm -rf "${root_mnt}"
    }
    trap "disk_provision_cleanup '${root_mnt}' '${qemu_nbd}'" EXIT

    local root_dev="/dev/nbd0p1"

    # Grow the ext4 filesystem to occupy all the disk space.
    print_info "[provision-disk] Growing filesystem..."
    sudo parted /dev/nbd0 --script resizepart 1 100%
    sudo e2fsck -f ${root_dev} # > /dev/null 2>&1
    sudo resize2fs ${root_dev} # > /dev/null 2>&1

    print_info "[provision-disk] Mounting root filesystem ${root_dev} at ${root_mnt}..."
    sudo mkdir -p "${root_mnt}"
    sudo mount "${root_dev}" "${root_mnt}"

    # Make sure DNS works inside chroot.
    sudo install -m 644 /etc/resolv.conf "${root_mnt}/etc/resolv.conf"

    print_info "[provision-disk] Bind-mounting /dev /proc /sys /run..."
    for d in dev proc sys run; do
        sudo mount --bind "/${d}" "${root_mnt}/${d}"
    done

    print_info "[provision] Running provisioning commands inside chroot..."
    sudo GUEST_KERNEL_VERSION=${GUEST_KERNEL_VERSION} LC_ALL=C LANG=C chroot "${root_mnt}" /bin/bash <<'EOF'
set -euo pipefail

echo "[provision/chroot] Starting..."

# Force IPv4 in the chroot.
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

export DEBIAN_FRONTEND=noninteractive

echo "[provision/chroot] apt-get update & base packages..."
apt-get update > /dev/null 2>&1
apt-get install -y \
    build-essential \
    ca-certificates \
    curl \
    docker.io \
    git \
    libfontconfig1-dev \
    libssl-dev \
    "linux-modules-extra-${GUEST_KERNEL_VERSION}" \
    python3-venv \
    pkg-config \
    sudo > /dev/null 2>&1

# Run depmod to re-configure kernel modules.
depmod -a "${GUEST_KERNEL_VERSION}"

# Ensure ubuntu user exists and adjust UID to 2000 if needed
if id ubuntu >/dev/null 2>&1; then
    U_OLD_UID="$(id -u ubuntu)"
    if [ "${U_OLD_UID}" -eq 1000 ]; then
        echo "[provision/chroot] Changing ubuntu UID/GID from 1000 to 2000..."
        # Make sure 2000 is free
        if getent passwd 2000 >/dev/null; then
            echo "[provision/chroot] UID 2000 already in use, aborting UID change" >&2
            exit 1
        fi
        if getent group 2000 >/dev/null; then
            echo "[provision/chroot] GID 2000 already in use, aborting GID change" >&2
            exit 1
        fi
        groupmod -g 2000 ubuntu
        usermod  -u 2000 ubuntu

        echo "[provision/chroot] Fixing ownership for UID/GID 1000..."
        for path in /home /var /etc; do
            find "$path" -xdev -uid 1000 -exec chown -h 2000 {} \; || true
            find "$path" -xdev -gid 1000 -exec chgrp -h 2000 {} \; || true
        done
    else
        echo "[provision/chroot] ubuntu UID is ${U_OLD_UID}, leaving as-is."
    fi
else
    echo "[provision/chroot] ubuntu user not found, creating with UID 2000..."
    groupadd -g 2000 ubuntu || true
    useradd -m -u 2000 -g 2000 -s /bin/bash ubuntu
fi

echo "[provision/chroot] Ensuring groups docker, sevguest, sudo memberships..."
groupadd -r docker > /dev/null 2>&1 || true
groupadd -r sevguest >/dev/null 2>&1 || true
usermod -aG sudo,docker,sevguest ubuntu || true

# Allow ubuntu user to use sudo without a password.
echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu-nopasswd
chmod 440 /etc/sudoers.d/ubuntu-nopasswd

echo "[provision/chroot] Writing /etc/udev/rules.d/90-sev-guest.rules..."
cat >/etc/udev/rules.d/90-sev-guest.rules <<'RULE'
KERNEL=="sev-guest", GROUP="sevguest", MODE="0660"
RULE

echo "[provision/chroot] Enabling docker & sshd..."
# systemctl enable will just manipulate symlinks; OK even if systemd not running
systemctl enable docker > /dev/null 2>&1 || true
systemctl enable ssh > /dev/null 2>&1 || systemctl enable ssh.service > /dev/null 2>&1 || true

echo "[provision/chroot] Installing rustup for ubuntu..."
su -l ubuntu -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1' || true

# FIXME: remove branch name and build some deps.
echo "[provision/chroot] Cloning Accless repo (idempotent)..."
su -l ubuntu -c '
    cd /home/ubuntu &&
    if [ ! -d accless/.git ]; then
        git clone -b feature-escrow-func https://github.com/faasm/tless.git accless > /dev/null 2>&1;
    else
        echo "accless repo already present, skipping clone";
    fi
' || true

# (Optional) You *could* pull docker images here, but it's messy because dockerd
# isn't running inside the chroot. Leaving that for runtime (cloud-init or first use).

echo "[provision/chroot] Provisioning done."
EOF

    disk_provision_cleanup ${root_mnt} ${qemu_nbd}
    print_success "Done provisioning disk image!"
}

#
# Fetch the disk image.
#
fetch_disk_image() {
    print_info "Fetching cloud-init disk image..."
    wget \
        https://cloud-images.ubuntu.com/noble/20251113/noble-server-cloudimg-amd64.img \
        -O ${OUTPUT_DIR}/disk.img > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "cloud-init disk image fetched successfully."
    else
        print_error "Failed to fetch cloud-init disk image."
        exit 1
    fi

    local qemu_img="${OUTPUT_DIR}/qemu/qemu-${QEMU_VERSION}/build/qemu-img"
    ${qemu_img} resize "${OUTPUT_DIR}/disk.img" +20G > /dev/null 2>&1
    print_success "cloud-init disk image resized successfully."

    provision_disk_image
}

#
# Generate ephemeral keypair for VM.
#
generate_ephemeral_keys() {
    print_info "Generating ephemeral keypair..."
    ssh-keygen -q -t ed25519 -N "" -f ${OUTPUT_DIR}/snp-key <<< y >/dev/null 2>&1
    print_info "Keypair generated succesfully!"
}

#
# Prepare the cloudinit overlay disk image.
#
prepare_cloudinit_image() {
    print_info "Preparing cloud-init overlay image..."

    local in_dir="${THIS_DIR}/cloud-init"
    local out_dir="${OUTPUT_DIR}/cloud-init"

    mkdir -p ${out_dir}
    cp ${in_dir}/meta-data.in ${out_dir}/meta-data
    ACCLESS_VERSION=$(cat "${ROOT_DIR}/VERSION") \
    GUEST_KERNEL_VERSION=${GUEST_KERNEL_VERSION} \
    SSH_PUB_KEY=$(cat "${OUTPUT_DIR}/snp-key.pub") \
    envsubst '${ACCLESS_VERSION} ${GUEST_KERNEL_VERSION} ${SSH_PUB_KEY}' \
        < ${in_dir}/user-data.in > ${out_dir}/user-data

    cloud-localds "${OUTPUT_DIR}/seed.img" "${out_dir}/user-data" "${out_dir}/meta-data"

    print_success "cloud-init overlay prepared successfully!"
}

usage() {
    print_info "Usage: $0 [--clean] [--component <apt|qemu|ovmf|kernel|disk|keys|cloudinit>]"
    exit 1
}

main() {
    local component=""

    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --clean)
                clean
                shift
                ;;
            --component)
                if [[ -z "$2" || "$2" == --* ]]; then
                    echo "Error: --component requires a value."
                    usage
                fi
                component="$2"
                shift 2
                ;;
            -h | --help)
                usage
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
    done

    if [[ -n "$component" ]]; then
        case "$component" in
            apt)
                install_apt_deps
                ;;
            qemu)
                build_qemu
                ;;
            ovmf)
                build_ovmf
                ;;
            kernel)
                fetch_kernel
                ;;
            disk)
                fetch_disk_image
                ;;
            keys)
                generate_ephemeral_keys
                ;;
            cloudinit)
                prepare_cloudinit_image
                ;;
            *)
                print_error "Error: Invalid component '$component'"
                usage
                ;;
        esac
    else
        install_apt_deps
        build_qemu
        build_ovmf
        fetch_kernel
        fetch_disk_image
        generate_ephemeral_keys
        prepare_cloudinit_image
    fi
}

main "$@"

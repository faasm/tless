#!/bin/bash

set -euo pipefail

THIS_DIR="$(dirname "$(realpath "$0")")"
SCRIPTS_DIR="${THIS_DIR}/.."
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
        https://cloud-images.ubuntu.com/noble/20251113/unpacked/noble-server-cloudimg-amd64-vmlinuz-generic \
        -O ${OUTPUT_DIR}/vmlinuz-noble > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_success "Linux kernel fetched successfully."
    else
        print_error "Failed to fetch Linux kernel."
        exit 1
    fi
}

#
# Fetch the linux kernel image.
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
    INSTANCE_ID="accless-snp-$(date +%s)" envsubst '${INSTANCE_ID}' \
        < ${in_dir}/meta-data.in > ${out_dir}/meta-data
    SSH_PUB_KEY=$(cat "${OUTPUT_DIR}/snp-key.pub") envsubst '${SSH_PUB_KEY}' \
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

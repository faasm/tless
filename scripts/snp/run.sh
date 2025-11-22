#!/bin/bash

set -euo pipefail

THIS_DIR="$(dirname "$(realpath "$0")")"
SCRIPTS_DIR="${THIS_DIR}/.."
OUTPUT_DIR="${THIS_DIR}/output"

source "${SCRIPTS_DIR}/common/utils.sh"
source "${THIS_DIR}/versions.sh"

#
# Helper method to get the C-bit position directly from hardware.
#
get_cbitpos() {
	modprobe cpuid
	local ebx=$(sudo dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 2> /dev/null | tail -c 16 | od -An -t u4 -j 4 -N 4 | sed -re 's|^ *||')
	local cbitpos=$((ebx & 0x3f))
    echo $cbitpos
}

#
# Run an SNP guest using QEMU.
#
run_qemu() {
    local qemu_dir="${OUTPUT_DIR}/qemu/qemu-${QEMU_VERSION}"
    local qemu="${qemu_dir}/build/qemu-system-x86_64"
    local qemu_bios_dir="${qemu_dir}/pc-bios"

    local kernel="${OUTPUT_DIR}/vmlinuz-noble"
    local initrd="${OUTPUT_DIR}/initrd-noble"
    local ovmf="${OUTPUT_DIR}/ovmf/ovmf-${OVMF_VERSION}/Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd"
    local disk_image="${OUTPUT_DIR}/disk.img"
    local seed_image="${OUTPUT_DIR}/seed.img"
    local cbitpos=$(get_cbitpos)

    # Can SSH into the VM witih:
    # ssh -p 2222 -i ${OUTPUT_DIR}/snp-key ubuntu@localhost
    ${qemu} \
        -L "${qemu_bios_dir}" \
        -enable-kvm \
        -nographic \
        -machine q35,confidential-guest-support=sev0,vmport=off \
        -cpu EPYC-v4 \
        -smp 6 -m 6G \
        -bios ${ovmf} \
        -kernel ${kernel} \
        -append "root=/dev/vda1 console=ttyS0" \
        -initrd ${initrd} \
        -object memory-backend-memfd,id=ram1,size=6G,share=true,prealloc=false \
        -machine memory-backend=ram1 \
        -object sev-snp-guest,id=sev0,cbitpos=${cbitpos},reduced-phys-bits=1,kernel-hashes=on \
        -drive "if=virtio,format=qcow2,file=${disk_image}" \
        -drive "if=virtio,format=raw,file=${seed_image}" \
        -netdev user,id=net0,hostfwd=tcp::2222-:22 \
        -device e1000,netdev=net0
}

run_qemu

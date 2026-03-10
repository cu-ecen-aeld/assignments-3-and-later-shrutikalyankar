#!/bin/bash
# build-driver.sh
# Run this from the aesd-char-driver directory.
# Set BUILDROOT_DIR to your buildroot checkout path before running.

BUILDROOT_DIR=${BUILDROOT_DIR:-"$(pwd)/../../buildroot"}

export ARCH=arm64
export CROSS_COMPILE=aarch64-buildroot-linux-gnu-
export KERNELDIR="${BUILDROOT_DIR}/output/build/linux-$(ls ${BUILDROOT_DIR}/output/build/ | grep '^linux-' | head -1 | sed 's/linux-//')"

# Add buildroot cross-compiler to PATH
export PATH="${BUILDROOT_DIR}/output/host/bin:${PATH}"

echo "Using KERNELDIR=${KERNELDIR}"
echo "Using CROSS_COMPILE=${CROSS_COMPILE}"

make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} KERNELDIR=${KERNELDIR}

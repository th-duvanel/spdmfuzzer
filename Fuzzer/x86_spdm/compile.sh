#!/bin/bash

git clone https://github.com/buildroot/buildroot.git
cd buildroot
git checkout 2023.08
make qemu_x86_64_defconfig
cp ../files/broot/.config ./buildroot
make
cd ..

git clone https://github.com/DMTF/libspdm.git
cd libspdm
git checkout dc48779a5b8c9199b01549311922e05429af2a0e
git submodule update --init --recursive

git am --3way --ignore-space-change --keep-cr ../patches/libspdm/0*.patch
cp ../patches/libspdm/config.h os_stub/mbedtlslib/include/mbedtls/
cp ../files/libspdm/CMakeLists.txt ./
cp ../files/libspdm/debuglib.h ./include/hal/library/

mkdir build_x64
cd build_x64
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key
make
cd ..

mkdir build_buildroot
cd build_buildroot
cmake -DARCH=x64 -DTOOLCHAIN=BUILDROOT -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key
make
cd ..

mkdir build_buildroot_userspace
cd build_buildroot_userspace
cmake -DARCH=x64 -DTOOLCHAIN=BUILDROOT_USERSPACE -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key
make
cd ..


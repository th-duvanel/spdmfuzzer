#!/bin/bash

git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu
git checkout 8d5a74e5b8dc8618556df0c5c81f76ddda8a5727
git submodule update --init --recursive

cp ../files/spdm-emu/CMakeLists.txt ./
cp ../files/libspdm/CMakeLists.txt libspdm/
cp -r ../files/libpsdm/unit_test/sample_key/ libspdm/unit_test/sample_key/

mkdir build
cd build
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=mbedtls ..
make copy_sample_key
make

cd ../../


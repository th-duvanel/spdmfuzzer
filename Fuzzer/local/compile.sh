#!/bin/bash

git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu
git checkout 8d5a74e5b8dc8618556df0c5c81f76ddda8a5727
git submodule update --init --recursive

mv ../files/spdm-emu/CMakeLists.txt ./
mv ../files/libspdm/CMakeLists.txt libspdm/

mkdir build
cd build
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key
make

ln -s ./spdm-emu/build/bin/spdm_responder_emu spdm_responder_emu
ln -s ./spdm-emu/build/bin/spdm_requester_emu spdm_requester_emu

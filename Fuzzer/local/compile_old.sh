#!/bin/bash

# A script for compilling an older SPDM version.
# This is the 16/Dec/2020 version, without GET_MEASUREMENTS 
# fix, from openspdm. Includes the testing emulator which
# uses transport headers.

git clone https://github.com/jyao1/openspdm
cd openspdm
git checkout 5c45f11354a5d77e399caf693fa2f66a38beccac

cd ..
wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz
wget https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz
wget https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/mbedtls-2.16.6.tar.gz

tar -xzf openssl-1.1.1g.tar.gz
tar -xf cmocka-1.1.5.tar.xz
tar -xzf mbedtls-2.16.6.tar.gz

rm openssl-1.1.1g.tar.gz
rm cmocka-1.1.5.tar.xz
rm mbedtls-2.16.6.tar.gz

mv openssl* ./openspdm/OsStub/OpensslLib/openssl
mv mbedtls* ./openspdm/OsStub/MbedTlsLib/mbedtls
mv cmocka* ./openspdm/UnitTest/CmockaLib/cmocka

cp -r ./files/openspdm/OsTest/* ./openspdm/OsTest/

cd openspdm
awk '/TOOLCHAIN STREQUAL "GCC"/,/SET(CMAKE_C_LINK_EXECUTABLE)/ { gsub("-Werror", "-Wno-error=unused-but-set-variable"); } { print }' CMakeLists.txt | sponge CMakeLists.txt
mkdir build
cd build
cmake -DARCH=X64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=MbedTls -DTESTTYPE=OsTest ..
make CopyTestKey
make

cd ..


exit 0

#!/bin/bash

# This is a script for compilling an older SPDM version.
# This is the 14/Dec/2020 version, from openspdm.

git clone https://github.com/jyao1/openspdm
cd openspdm
git checkout bc1be2b474860c3935e03e5d3444865b8f46760a

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

cd openspdm
mkdir build
cd build
cmake -DARCH=X64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=MbedTls -DTESTTYPE=OsTest ..
make CopyTestKey
make

cd ..
#!/bin/bash

# Thiago Duvanel Ferreira
# thiago.duvanel@usp.br

# A script for compilling an older SPDM version.
# This is the 16/Dec/2020 version, without GET_MEASUREMENTS 
# fix, from openspdm. Includes the testing emulator which
# uses transport headers.

# Um script para compilar uma versão mais antiga do SPDM.
# Esta é a versão de 16/Dez/2020, sem a correção do GET_MEASUREMENTS,
# do openspdm. Inclui o emulador de testes que
# usa cabeçalhos de transporte.

verify_deps() {
    programs=("gcc" "git" "make" "g++" "wget" "tar" "awk" "cmake" "sponge" "xz")
    missing_programs=()

    for program in "${programs[@]}"; do
        if ! command -v "$program" &> /dev/null; then
            missing_programs+=("$program")
        fi
    done

    if [ ${#missing_programs[@]} -ne 0 ]; then
        echo "The following programs are missing: ${missing_programs[*]}"

        exit 1
    else
        echo "All necessary programs are installed. Continuing..."
    fi
}

verify_deps

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

# Necessary for libs installation.
# Necessário para instalação das bibliotecas.
mv openssl* ./openspdm/OsStub/OpensslLib/openssl
mv mbedtls* ./openspdm/OsStub/MbedTlsLib/mbedtls
mv cmocka* ./openspdm/UnitTest/CmockaLib/cmocka

# Necessary for emulation packet headers fix compatibiliyy
# with spdmfuzzer and new certificates, since the version is
# from 2020, the certificates are expired.

# Necessário para compatibilidade de correção de cabeçalhos de pacotes de emulação
# com o spdmfuzzer e novos certificados, já que a versão é
# de 2020, os certificados estão expirados.
cp -r ./files/openspdm/OsTest/* ./openspdm/OsTest/

cd openspdm
awk '/TOOLCHAIN STREQUAL "GCC"/,/SET(CMAKE_C_LINK_EXECUTABLE)/ { gsub("-Werror", "-Wno-error=unused-but-set-variable"); } { print }' CMakeLists.txt | sponge CMakeLists.txt
mkdir build
cd build
cmake -DARCH=X64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=MbedTls -DTESTTYPE=OsTest ..
make CopyTestKey
make

cd ../..

make

exit 0

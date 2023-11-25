CMOCKAurl = https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz
MBEDTLSurl = https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/mbedtls-2.16.6.tar.gz
OPENSSLurl = https://www.openssl.org/source/openssl-1.1.1g.tar.gz
SPDMurl = https://github.com/jyao1/openspdm.git
TLSFZZRurl = https://github.com/tlsfuzzer/tlsfuzzer.git

CMOCKAfile = cmocka-1.1.5.tar.xz
MBEDTLSfile = mbedtls-2.16.6.tar.gz
OPENSSLfile = openssl-1.1.1g.tar.gz

SPDMhash = a918497a32b412e843c29ef36d26c4668b582e46
TLSFZZRhash = 4e68c41aa029b5303d3acf03050072a0e9be64d5

# SPDM configs:
TOOLCHAIN = GCC
TARGET = Release
CRYPTO = MbedTls
TSTTYPE = OsTest

.PHONY: all

all:
	git clone $(SPDMurl)
	git --git-dir=./openspdm/.git --work-tree=./openspdm checkout -b tester $(SPDMhash)
	cp GNUmakefile.Flags ./openspdm/GNUmakefile.Flags

	$(MAKE) cmocka
	$(MAKE) mbedtls
	$(MAKE) openssl

	$(MAKE) openspdm_tls
	$(MAKE) tlsfuzzer

	$(MAKE) clean


cmocka:
	wget $(CMOCKAurl)
	@tar -xvf $(CMOCKAfile)
	mv cmocka-1.1.5 cmocka
	mv cmocka openspdm/UnitTest/CmockaLib


mbedtls:
	wget $(MBEDTLSurl) -O $(MBEDTLSfile)
	@tar -xvf $(MBEDTLSfile)
	mv mbedtls-mbedtls-2.16.6 mbedtls
	mv mbedtls openspdm/OsStub/MbedTlsLib


openssl:
	wget $(OPENSSLurl)
	@tar -xvf $(OPENSSLfile)
	mv openssl-1.1.1g openssl
	mv openssl openspdm/OsStub/OpensslLib


openspdm:
	@$(MAKE) -C openspdm -f GNUmakefile ARCH=X64 TARGET=DEBUG CRYPTO=MbedTls -e WORKSPACE=.
	mv ./openspdm/Build/DEBUG_GCC/X64 ./openspdm/Build/DEBUG_GCC/TLS_X64


	@$(MAKE) -C openspdm -f GNUmakefile ARCH=X64 TARGET=RELEASE CRYPTO=MbedTls -e WORKSPACE=.
	mv ./openspdm/Build/RELEASE_GCC/X64 ./openspdm/Build/RELEASE_GCC/TLS_X64


	@$(MAKE) -C openspdm -f GNUmakefile ARCH=X64 TARGET=DEBUG CRYPTO=Openssl -e WORKSPACE=.
	mv ./openspdm/Build/DEBUG_GCC/X64 ./openspdm/Build/DEBUG_GCC/SSL_X64


	@$(MAKE) -C openspdm -f GNUmakefile ARCH=X64 TARGET=RELEASE CRYPTO=Openssl -e WORKSPACE=.
	mv ./openspdm/Build/RELEASE_GCC/X64 ./openspdm/Build/RELEASE_GCC/SSL_X64

openspdm_tls:
	@$(MAKE) -C openspdm -f GNUmakefile ARCH=X64 TARGET=RELEASE CRYPTO=MbedTls -e WORKSPACE=.
	mv ./openspdm/Build/RELEASE_GCC/X64 ./openspdm/Build/RELEASE_GCC/TLS_X64


tlsfuzzer:
	git -C ./Fuzzer clone $(TLSFZZRurl)
	git --git-dir=./tlsfuzzer/.git --work-tree=./tlsfuzzer checkout -b tester $(TLSFZZRhash)

clean:
	rm -f $(CMOCKAfile) $(MBEDTLSfile) $(OPENSSLfile)
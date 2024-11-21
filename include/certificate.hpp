#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#include "../include/utils.hpp"

void initialize_openssl();

EVP_PKEY* generate_private_key();

X509* create_x509_certificate(EVP_PKEY* pkey);

void sign_certificate(X509* x509, EVP_PKEY* pkey);

std::vector<uint8_t> encode_certificate(X509* x509);

std::vector<uint8_t> create_certificate();
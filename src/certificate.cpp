#include "../include/certificate.hpp"

void initialize_openssl() {
    ERR_load_BIO_strings();
}

EVP_PKEY* generate_private_key() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);
    return pkey;
}

X509* create_x509_certificate(EVP_PKEY* pkey) {
    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"My Organization", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"example.com", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    return x509;
}

void sign_certificate(X509* x509, EVP_PKEY* pkey) {
    X509_sign(x509, pkey, EVP_sha256());
}

std::vector<uint8_t> encode_certificate(X509* x509) {
    std::vector<uint8_t> der_cert;
    int len = i2d_X509(x509, nullptr);
    if (len > 0) {
        der_cert.resize(len);
        uint8_t* p = der_cert.data();
        i2d_X509(x509, &p);
    }
    return der_cert;
}

std::vector<uint8_t> create_certificate() {
    initialize_openssl();
    EVP_PKEY* pkey = generate_private_key();
    X509* x509 = create_x509_certificate(pkey);
    sign_certificate(x509, pkey);
    std::vector<uint8_t> der_cert = encode_certificate(x509);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return der_cert;
}
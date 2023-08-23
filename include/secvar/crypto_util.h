#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include "crypto.h"

int validate_x509_certificate (crypto_x509_t *x509);
int get_pkcs7_certificate (const uint8_t *cert_data, size_t cert_data_len, crypto_pkcs7_t **pkcs7_cert);

#endif
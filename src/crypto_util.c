/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include <stdint.h>
#include <string.h>
#include "secvar/crypto_util.h"
#include "secvar/crypto.h"
#include "libstb-secvar-errors.h"

int validate_x509_certificate (crypto_x509_t *x509)
{
  int len = 0;

  if (x509 == NULL)
    return SV_UNEXPECTED_CERT_SIZE;

  len = crypto_x509_get_der_len (x509);
  if (len <= 0)
    return SV_UNEXPECTED_CRYPTO_ERROR;

  len = crypto_x509_get_tbs_der_len (x509);
  if (len <= 0)
    return SV_UNEXPECTED_CRYPTO_ERROR;

  if (crypto_x509_get_version (x509) != 3)
    return SV_X509_ERROR;

  if (!crypto_x509_is_RSA (x509))
    return SV_UNEXPECTED_CERT_ALGO;

  len = crypto_x509_get_sig_len (x509);
  if (len <= 0)
    /* dont want to accidentally return 0 (SUCCESS) */
    return len ? len : SV_UNEXPECTED_CRYPTO_ERROR;

  len = crypto_x509_get_pk_bit_len (x509);
  if (len != 2048 && len != 3072 && len != 4096)
    return SV_UNEXPECTED_CERT_SIZE;

  return SV_SUCCESS;
}

int get_pkcs7_certificate (const uint8_t *cert_data, size_t cert_data_len, crypto_pkcs7_t **pkcs7_cert)
{
  crypto_pkcs7_t *pkcs7;

  pkcs7 = crypto_pkcs7_parse_der (cert_data, cert_data_len);
  if (!pkcs7)
    return SV_PKCS7_PARSE_ERROR;

  /* make sure digest alg is sha256 */
  if (crypto_pkcs7_md_is_sha256 (pkcs7) != CRYPTO_SUCCESS)
  {
    crypto_pkcs7_free(pkcs7);
    return SV_UNEXPECTED_PKCS7_ALGO;
  }

  *pkcs7_cert = pkcs7;

  return SV_SUCCESS;
}

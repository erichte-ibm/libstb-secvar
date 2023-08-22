/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include <stdint.h>
#include <string.h>
#include "secvar/crypto.h"
#include "libstb-secvar-errors.h"

static int
validate_x509_certificate (crypto_x509_t *x509)
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
  if (len != 2048 && len != 4096)
    return SV_UNEXPECTED_CERT_SIZE;

  return SV_SUCCESS;
}

static int
get_pkcs7_certificate (const uint8_t *cert_data, size_t cert_data_len, crypto_pkcs7_t **pkcs7_cert)
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

#ifdef SECVAR_CRYPTO_WRITE_FUNC

hash_func_t hash_functions[] = {
  { .name = "SHA1", .size = 20, .crypto_md_funct = CRYPTO_MD_SHA1, .guid = &PKS_CERT_SHA1_GUID },
  { .name = "SHA224", .size = 28, .crypto_md_funct = CRYPTO_MD_SHA224, .guid = &PKS_CERT_SHA224_GUID },
  { .name = "SHA256", .size = 32, .crypto_md_funct = CRYPTO_MD_SHA256, .guid = &PKS_CERT_SHA256_GUID },
  { .name = "SHA384", .size = 48, .crypto_md_funct = CRYPTO_MD_SHA384, .guid = &PKS_CERT_SHA384_GUID },
  { .name = "SHA512", .size = 64, .crypto_md_funct = CRYPTO_MD_SHA512, .guid = &PKS_CERT_SHA512_GUID },
};

hash_func_t x509_hash_functions[] = {
  { .name = "SHA256", .size = 32, .crypto_md_funct = CRYPTO_MD_SHA256, .guid = &PKS_CERT_X509_SHA256_GUID },
  { .name = "SHA384", .size = 48, .crypto_md_funct = CRYPTO_MD_SHA384, .guid = &PKS_CERT_X509_SHA384_GUID },
  { .name = "SHA512", .size = 64, .crypto_md_funct = CRYPTO_MD_SHA512, .guid = &PKS_CERT_X509_SHA512_GUID },
};
#endif

crypto_func_t crypto = {
                         .get_pkcs7_certificate = get_pkcs7_certificate,
                         .validate_x509_certificate = validate_x509_certificate,
                         };

/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "secvar/crypto.h"
#include "libstb-secvar-errors.h"

/* X509 */

static bool
x509_is_CA (crypto_x509_t *x509)
{
  if (X509_check_ca (x509) == 1)
    return true;

  return false;
}

static int
x509_get_der_len (crypto_x509_t *x509, size_t *size)
{
  int rc;

  rc = i2d_X509 (x509, NULL);
  if (rc < 0)
    return SV_UNEXPECTED_CRYPTO_ERROR;

  *size = rc;

  return SV_SUCCESS;
}

static int
x509_get_tbs_der_len (crypto_x509_t *x509, size_t *size)
{
  int rc;

  rc = i2d_re_X509_tbs (x509, NULL);
  if (rc < 0)
    return SV_UNEXPECTED_CRYPTO_ERROR;

  *size = rc;

  return SV_SUCCESS;
}

static int
x509_get_version (crypto_x509_t *x509)
{
  /*
   * add one because function return one less than actual certificate version,
   * see https://www.openssl.org/docs/man1.1.0/man3/X509_get_version.html
   */
  return X509_get_version (x509) + 1;
}

static bool
x509_is_RSA (crypto_x509_t *x509)
{
  EVP_PKEY *pub = NULL;
  bool rc;

  pub = X509_get_pubkey (x509);
  if (!pub)
    {
      prlog (PR_ERR, "ERROR: Failed to extract public key from x509\n");
      return false;
    }
#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR < 3
  RSA *rsa = NULL;
  rsa = EVP_PKEY_get1_RSA (pub);
  if (!rsa)
    {
      prlog (PR_ERR, "ERROR: Failed to extract RSA information from public key "
                     "of x509\n");
      EVP_PKEY_free (pub);
      return false;
    }

  RSA_free (rsa);
  rc = true;
#else
  int pk_type;
  pk_type = EVP_PKEY_base_id (pub);
  if (pk_type == NID_undef)
    {
      prlog (PR_ERR, "ERROR: Failed to extract key type from x509\n");
      rc = false;
    }
  else if (pk_type != EVP_PKEY_RSA)
    rc = false;
  else
    rc = true;
#endif

  EVP_PKEY_free (pub);
  return rc;
}

int
x509_get_pk_bit_len (crypto_x509_t *x509, size_t *size)
{
  EVP_PKEY *pub = NULL;
  int length;

  pub = X509_get_pubkey (x509);
  if (!pub)
    {
      prlog (PR_ERR, "ERROR: Failed to extract public key from x509\n");
      return SV_X509_ERROR;
    }

#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR < 3
  RSA *rsa = NULL;
  rsa = EVP_PKEY_get1_RSA (pub);
  if (!rsa)
    {
      prlog (PR_ERR, "ERROR: Failed to extract RSA information from public key "
                     "of x509\n");
      return SV_X509_ERROR;
    }
  length = RSA_bits (rsa);
  RSA_free (rsa);
#else
  if (EVP_PKEY_get_base_id (pub) != EVP_PKEY_RSA)
    {
      prlog (PR_ERR, "ERROR: Public key of x509 is not of type RSA\n");
      EVP_PKEY_free (pub);
      return SV_X509_ERROR;
    }

  length = EVP_PKEY_get_bits (pub);
#endif
  if (!length)
    {
      prlog (PR_ERR, "ERROR: Failed to extract key length from RSA public key "
                     "of x509\n");
      EVP_PKEY_free (pub);
      return SV_X509_ERROR;
    }

  EVP_PKEY_free (pub);
  *size = length;
  return SV_SUCCESS;
}

static int
x509_get_sig_len (crypto_x509_t *x509, size_t *len)
{
  int rc = SV_SUCCESS;
  ASN1_BIT_STRING *sig;

  sig = X509_get0_pubkey_bitstr (x509);
  if (!sig)
    {
      prlog (PR_ERR, "ERROR: Could not extract signature length from x509\n");

      rc = ERR_get_error ();
      rc = !rc ? ERR_PACK (ERR_LIB_X509, 0, X509_R_INVALID_FIELD_NAME) : rc;
      if (rc >= 0)
        rc *= -1;

      return rc;
    }

  *len = sig->length;

  return rc;
}

static int
x509_oid_is_pkcs1_sha256 (crypto_x509_t *x509)
{
  int rc;
  const X509_ALGOR *alg = NULL;

  alg = X509_get0_tbs_sigalg (x509);
  if (!alg)
    {
      prlog (PR_ERR, "ERROR: Could not extract algorithm from X509\n");
      rc = ERR_get_error ();
      return !rc ? ERR_PACK (ERR_LIB_X509, 0, X509_R_UNSUPPORTED_ALGORITHM) : rc;
    }

  if (OBJ_obj2nid (alg->algorithm) != NID_sha256WithRSAEncryption)
    {
      rc = ERR_get_error ();
      return !rc ? ERR_PACK (ERR_LIB_X509, 0, X509_R_UNSUPPORTED_ALGORITHM) : rc;
    }

  return SV_SUCCESS;
}

static void
x509_free (crypto_x509_t *x509)
{
  X509_free (x509);
}

static int
pkcs7_parse_der (const unsigned char *buf, const int buflen, crypto_pkcs7_t **out)
{
  int rc;
  PKCS7 *pkcs7;

  uint8_t *data = NULL, *data_orig;
  int len;

  pkcs7 = d2i_PKCS7 (NULL, &buf, buflen);
  if (!pkcs7)
    {
      PKCS7_SIGNED *signed_data;
      /*
       * Something could be wrong, or it could be that we've been
       * given a signedData instead of a full message.
       */
      signed_data = d2i_PKCS7_SIGNED (NULL, &buf, buflen);
      if (signed_data)
        {
          *out = signed_data;
          return SV_SUCCESS;
        }
      else
        {
          prlog (PR_ERR, "ERROR: parsing PKCS7 with OpenSSL failed\n");
          return SV_PKCS7_PARSE_ERROR;
        }
    }

  /* make sure it contains signed data, openssl supports other types */
  rc = PKCS7_type_is_signed (pkcs7);
  if (!rc)
    {
      prlog (PR_ERR, "ERROR: PKCS7 does not contain signed data\n");
      rc = SV_PKCS7_PARSE_ERROR;
      goto out;
    }

  rc = SV_SUCCESS;
  /* create a standalone copy of just the SIGNED part */
  len = i2d_PKCS7_SIGNED (pkcs7->d.sign, &data);
  if (len < 0)
    {
      prlog (PR_ERR, "ERROR: OpenSSL could not convert signed part to DER: %d\n", len);
      rc = SV_UNEXPECTED_CRYPTO_ERROR;
      goto out;
    }

  data_orig = data;
  *out = d2i_PKCS7_SIGNED (NULL, (const uint8_t **) &data, len);
  if (!*out)
    {
      prlog (PR_ERR,
             "ERROR: OpenSSL could not parse its own signed part DER!\n");
      rc = SV_UNEXPECTED_CRYPTO_ERROR;
    }

  OPENSSL_free (data_orig);

out:
  PKCS7_free (pkcs7);

  return rc;
}

static int
pkcs7_md_is_sha256 (crypto_pkcs7_t *pkcs7)
{
  X509_ALGOR *alg;
  /*
   * extract signer algorithms from pkcs7
   * we successfully parsed the PKCS#7 message so we do not expect
   * this to fail
   */
  alg = sk_X509_ALGOR_value (pkcs7->md_algs, 0);
  if (!alg)
    {
      prlog (PR_ERR, "ERROR: Could not extract message digest identifiers from "
                     "PKCS7\n");
      return SV_PKCS7_ERROR;
    }

  /* extract nid from algorithms and ensure it is the same nid as SHA256 */
  if (OBJ_obj2nid (alg->algorithm) == NID_sha256)
    return SV_SUCCESS;
  else
    return SV_UNEXPECTED_PKCS7_ALGO;
}

static void
pkcs7_free (crypto_pkcs7_t *pkcs7)
{
  PKCS7_SIGNED_free (pkcs7);
}

static crypto_x509_t *
pkcs7_get_signing_cert (crypto_pkcs7_t *pkcs7, int cert_num)
{
  X509 *pkcs7_cert = NULL;

  pkcs7_cert = sk_X509_value (pkcs7->cert, cert_num);

  return pkcs7_cert;
}

/*
 * currently this function works and the mbedtls version currently perform the following steps
 *   1. the hash, md context and given x509 are used to generated a signature
 *   2. all of the signatures in the pkcs7 are compared to the signature generated by the x509
 *   3. if any of the signatures in the pkcs7 match the genrated signature then return SV_SUCCESS
 */
static int
pkcs7_signed_hash_verify (crypto_pkcs7_t *pkcs7, crypto_x509_t *x509, unsigned char *hash, int hash_len)
{
  int rc, exp_size, md_nid, num_signers;
  unsigned char *exp_sig;
  EVP_PKEY *pk;
  EVP_PKEY_CTX *pk_ctx;
  X509_ALGOR *alg;
  const EVP_MD *evp_md;
  PKCS7_SIGNER_INFO *signer_info;

  /* generate a signature with the x509 */
  pk = X509_get_pubkey (x509);
  pk_ctx = EVP_PKEY_CTX_new (pk, NULL);
  if (pk == NULL || pk_ctx == NULL)
    {
      prlog (PR_ERR, "ERROR: Failed to create public key context from x509\n");
      return SV_X509_ERROR;
    }
  if (EVP_PKEY_verify_init (pk_ctx) <= 0)
    {
      prlog (PR_ERR, "ERROR: Failed to initialize pk context for x509 pk \n");
      rc = SV_X509_ERROR;
      goto out;
    }
  if (EVP_PKEY_CTX_set_rsa_padding (pk_ctx, RSA_PKCS1_PADDING) <= 0)
    {
      prlog (PR_ERR, "ERROR: Failed to setup pk context with RSA padding\n");
      rc = SV_X509_ERROR;
      goto out;
    }
  /* extract signer algorithms from pkcs7 */
  alg = sk_X509_ALGOR_value (pkcs7->md_algs, 0);
  if (!alg)
    {
      prlog (PR_ERR, "ERROR: Could not extract message digest identifiers from "
                     "PKCS7\n");
      rc = SV_PKCS7_ERROR;
      goto out;
    }
  /* extract nid from algorithms */
  md_nid = OBJ_obj2nid (alg->algorithm);
  /* set signature md depending on md in pkcs7 */
  evp_md = EVP_get_digestbynid (md_nid);
  if (!evp_md)
    {
      prlog (PR_ERR, "ERROR: Unknown NID (%d) for MD found in PKCS7\n", md_nid);
      rc = SV_UNEXPECTED_PKCS7_ALGO;
      goto out;
    }

  if (EVP_PKEY_CTX_set_signature_md (pk_ctx, evp_md) <= 0)
    {
      prlog (PR_ERR, "ERROR: Failed to set signature md for pk ctx\n");
      rc = SV_UNEXPECTED_CRYPTO_ERROR;
      goto out;
    }

  if (hash_len != EVP_MD_size (evp_md))
    {
      rc = SV_CRYPTO_USAGE_BUG;
      goto out;
    }

  /* verify on all signatures in pkcs7 */
  num_signers = sk_PKCS7_SIGNER_INFO_num (pkcs7->signer_info);
  if (num_signers == 0)
    {
      prlog (PR_ERR, "ERROR: no signers to verify");
      rc = SV_PKCS7_ERROR;
      goto out;
    }
  else if (num_signers < 0)
    {
      prlog(PR_ERR, "ERROR: pkcs7->signer_info was NULL");
      rc = SV_PKCS7_ERROR;
      goto out;
    }

  for (int s = 0; s < num_signers; s++)
    {
      /* make sure we can get the signature data */
      signer_info = sk_PKCS7_SIGNER_INFO_value (pkcs7->signer_info, s);

      if (!signer_info)
        {
          prlog (PR_ERR, "ERROR: Could not get PKCS7 signer information\n");
          rc = SV_PKCS7_ERROR;
          goto out;
        }

      exp_size = signer_info->enc_digest->length;
      exp_sig = signer_info->enc_digest->data;

      if (exp_size <= 0 || !exp_sig)
        {
          prlog (PR_ERR, "ERROR: No data found in PKCS7\n");
          rc = SV_PKCS7_ERROR;
          goto out;
        }
      rc = EVP_PKEY_verify (pk_ctx, exp_sig, exp_size, hash, hash_len);
      /*
       * returns 1 on success
       * if successfull then exit
       */
      if (rc == 1)
        goto out;
    }
out:
  EVP_PKEY_free (pk);
  EVP_PKEY_CTX_free (pk_ctx);

  if (rc == 1)
    return SV_SUCCESS;

  return SV_FAILED_TO_VERIFY_SIGNATURE;
}

static void
error_string (int rc, char *out_str, size_t out_max_len)
{
  ERR_error_string_n (rc, out_str, out_max_len);
}

static crypto_x509_t *
x509_parse_der (const unsigned char *data, size_t data_len)
{
  X509 *x509;
  x509 = d2i_X509 (NULL, &data, data_len);

  if (!x509)
    return NULL;

  return x509;
}

#ifdef SECVAR_CRYPTO_WRITE_FUNC
static int
x509_md_is_sha256 (crypto_x509_t *x509)
{
  int rc;
  const X509_ALGOR *alg = NULL;

  alg = X509_get0_tbs_sigalg (x509);
  if (!alg)
    {
      prlog (PR_ERR, "ERROR: Could not extract algorithm from X509\n");
      rc = ERR_get_error ();
      return !rc ? ERR_PACK (ERR_LIB_X509, 0, X509_R_INVALID_FIELD_NAME) : rc;
    }

  if (OBJ_obj2nid (alg->algorithm) == NID_sha256WithRSAEncryption)
    return SV_SUCCESS;
  else
    {
      prlog (PR_ERR, "ERROR: Certificate NID is not SHA256, expected %d found %d\n",
             NID_sha256, OBJ_obj2nid (alg->algorithm));
      rc = ERR_get_error ();
      return !rc ? ERR_PACK (ERR_LIB_X509, 0, X509_R_UNSUPPORTED_ALGORITHM) : rc;
    }
}

static void
x509_get_short_info (crypto_x509_t *x509, char *short_desc, size_t max_len)
{
  const X509_ALGOR *alg = NULL;
  alg = X509_get0_tbs_sigalg (x509);
  /* unlikely failure */
  if (!alg)
    {
      prlog (PR_ERR, "ERROR: Could not extract algorithm from X509\n");
      return;
    }
  /* last arg set as ZERO to get short description in string */
  OBJ_obj2txt (short_desc, max_len, alg->algorithm, 0);
}

static int
x509_get_long_desc (char *x509_info, size_t max_len, const char *delim, crypto_x509_t *x509)
{
  int rc;
  long actual_mem_len;
  BIO *bio = BIO_new (BIO_s_mem ());
  char *tmp = NULL;
  rc = X509_print_ex (bio, x509, XN_FLAG_MULTILINE,
                      X509_FLAG_COMPAT | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_SIGDUMP);
  if (rc < 0)
    {
      prlog (PR_ERR, "ERROR: could not get BIO data on X509, openssl err#%d\n", rc);
      return rc;
    }
  /* returns total data avialable */
  actual_mem_len = BIO_get_mem_data (bio, &tmp);
  /* check to make sure we do not overflow the allocated mem */
  actual_mem_len = max_len > actual_mem_len ? actual_mem_len : max_len - 1;
  memcpy (x509_info, tmp, actual_mem_len);
  BIO_free (bio);
  return actual_mem_len;
}

static int
x509_convert_pem_to_der (const unsigned char *input, size_t ilen, unsigned char **output, size_t *olen)
{
  int rc;
  char *header = NULL, *name = NULL;
  BIO *bio;

  bio = BIO_new_mem_buf (input, ilen);
  rc = !PEM_read_bio (bio, &name, &header, output, (long int *) olen);
  if (header)
    OPENSSL_free (header);

  if (name)
    OPENSSL_free (name);

  BIO_free (bio);

  return rc;
}

static int
pkcs7_generate_w_signature (unsigned char **pkcs7, size_t *pkcs7_size,
                            const unsigned char *new_data, size_t new_data_size,
                            const char **crt_files, const char **keyFiles,
                            int key_pairs, int hash_funct)
{
  int rc;
  PKCS7 *gen_pkcs7_struct = NULL;
  BIO *bio = NULL, *out_bio = NULL;
  FILE *fp;
  EVP_PKEY *evp_pkey = NULL;
  const EVP_MD *evp_md = NULL;
  crypto_x509_t *x509 = NULL;
  long pkcs7_out_len;
  unsigned char *key = NULL, *keyTmp, *crt = NULL, *out_bio_der = NULL;
  char *unnecessary_hdr = NULL, *unnecessary_name = NULL;
  long int keySize, crtSize;

  if (key_pairs == 0)
    {
      prlog (PR_ERR, "ERROR: No signers given, cannot generate PKCS7\n");
      return SV_CRYPTO_USAGE_BUG;
    }

  evp_md = EVP_get_digestbynid (hash_funct);
  if (!evp_md)
    {
      prlog (PR_ERR, "ERROR: Unknown NID (%d) for MD found in PKCS7\n", hash_funct);
      return SV_CRYPTO_USAGE_BUG;
    }

  bio = BIO_new_mem_buf (new_data, new_data_size);
  if (!bio)
    {
      prlog (PR_ERR, "ERROR: Failed to initialize new data BIO structure\n");
      rc = SV_UNEXPECTED_CRYPTO_ERROR;
      goto out;
    }

  gen_pkcs7_struct = PKCS7_sign (NULL, NULL, NULL, bio, PKCS7_PARTIAL | PKCS7_DETACHED);
  if (!gen_pkcs7_struct)
    {
      prlog (PR_ERR, "ERROR: Failed to initialize pkcs7 structure\n");
      rc = SV_UNEXPECTED_CRYPTO_ERROR;
      goto out;
    }
  /* for every key pair get the data and add the signer to the pkcs7 */
  for (int i = 0; i < key_pairs; i++)
    {
      /* get data of private keys */
      fp = fopen (keyFiles[i], "r");
      if (fp == NULL)
        {
          prlog (PR_ERR, "ERROR: failed to open file %s: %s\n", keyFiles[i],
                 strerror (errno));
          rc = SV_INVALID_FILE;
          goto out;
        }
      rc = PEM_read (fp, &unnecessary_name, &unnecessary_hdr, &key, &keySize);
      OPENSSL_free (unnecessary_name);
      OPENSSL_free (unnecessary_hdr);
      fclose (fp);
      /* returns 1 on success */
      if (rc != 1)
        {
          prlog (PR_ERR, "ERROR: failed to get data from priv key file %s\n", keyFiles[i]);
          rc = SV_INVALID_FILE;
          goto out;
        }
      /* get data from crt */
      fp = fopen (crt_files[i], "r");
      if (fp == NULL)
        {
          prlog (PR_ERR, "ERROR: failed to open file %s: %s\n", keyFiles[i],
                 strerror (errno));
          rc = SV_INVALID_FILE;
          goto out;
        }
      rc = PEM_read (fp, &unnecessary_name, &unnecessary_hdr, &crt, &crtSize);
      OPENSSL_free (unnecessary_name);
      OPENSSL_free (unnecessary_hdr);
      fclose (fp);
      /* returns 1 on success */
      if (rc != 1)
        {
          prlog (PR_ERR, "ERROR: failed to get data from cert file %s\n", crt_files[i]);
          rc = SV_INVALID_FILE;
          goto out;
        }
      /* get private key from private key DER buff */
      keyTmp = key;
      evp_pkey = d2i_AutoPrivateKey (NULL, (const unsigned char **) &keyTmp, keySize);
      if (!evp_pkey)
        {
          prlog (PR_ERR, "ERROR: Failed to parse private key into EVP_PKEY "
                         "openssl struct\n");
          rc = SV_INVALID_FILE;
          goto out;
        }
      /* get x509 from cert DER buff */
      x509 = x509_parse_der (crt, crtSize);
      if (!x509)
        {
          prlog (PR_ERR, "ERROR: Failed to parse certificate into x509 openssl "
                         "struct\n");
          rc = SV_INVALID_FILE;
          goto out;
        }
      /*
       * add the signature to the pkcs7
       * returns NULL is failure
       */
      if (!PKCS7_sign_add_signer (gen_pkcs7_struct, x509, evp_pkey, evp_md, PKCS7_NOATTR))
        {
          prlog (PR_ERR,
                 "ERROR: Failed to add signer to the pkcs7 structure\n");
          rc = SV_UNEXPECTED_CRYPTO_ERROR;
          goto out;
        }
      /* reset mem */
      OPENSSL_free (key);
      key = NULL;
      EVP_PKEY_free (evp_pkey);
      evp_pkey = NULL;
      OPENSSL_free (crt);
      crt = NULL;
      x509_free (x509);
      x509 = NULL;
    }

  /* finalize the struct, runs hashing and signatures */
  rc = PKCS7_final (gen_pkcs7_struct, bio, PKCS7_BINARY);
  if (rc != 1)
    {
      prlog (PR_ERR, "ERROR: Failed to finalize openssl pkcs7 struct\n");
      rc = SV_UNEXPECTED_CRYPTO_ERROR;
      goto out;
    }

  /* convert to DER */
  out_bio = BIO_new (BIO_s_mem ());
  if (!out_bio)
    {
      prlog (PR_ERR, "ERROR: Failed to initialize openssl BIO \n");
      rc = SV_ALLOCATION_FAILED;
      goto out;
    }

  /* returns 1 for success */
  rc = i2d_PKCS7_bio (out_bio, gen_pkcs7_struct);
  if (!rc)
    {
      prlog (PR_ERR, "ERROR: Failed to convert PKCS7 Struct to DER\n");
      rc = SV_UNEXPECTED_CRYPTO_ERROR;
      goto out;
    }

  /* get data out of BIO and into return values */
  pkcs7_out_len = BIO_get_mem_data (out_bio, &out_bio_der);
  /* returns number of bytes decoded or error */
  if (pkcs7_out_len <= 0)
    {
      prlog (PR_ERR,
             "ERROR: Failed to extract PKCS7 DER data from openssl BIO\n");
      rc = SV_UNEXPECTED_CRYPTO_ERROR;
      goto out;
    }

  *pkcs7 = OPENSSL_malloc (pkcs7_out_len);
  if (!*pkcs7)
    {
      prlog (PR_ERR, "ERROR: Failed to allocate memory\n");
      rc = SV_ALLOCATION_FAILED;
      goto out;
    }

  *pkcs7_size = pkcs7_out_len;
  /* copy memory over so it is persistent */
  memcpy (*pkcs7, out_bio_der, *pkcs7_size);
  /* if here then successfull generation */
  rc = SV_SUCCESS;

out:
  if (key)
    OPENSSL_free (key);

  if (crt)
    OPENSSL_free (crt);

  if (evp_pkey)
    EVP_PKEY_free (evp_pkey);

  if (x509)
    x509_free (x509);

  if (gen_pkcs7_struct)
    PKCS7_free (gen_pkcs7_struct);

  BIO_free (bio);
  BIO_free (out_bio);

  return rc;
}

static int
pkcs7_generate_w_already_signed_data (unsigned char **pkcs7, size_t *pkcs7_size,
                                      const unsigned char *new_data, size_t new_data_size,
                                      const char **crt_files, const char **sig_files,
                                      int key_pairs, int hash_funct)
{
  prlog (PR_ERR,
         "ERROR: Currently unable to support generation of PKCS7 with "
         "externally generated signatures when compiling with OpenSSL\n");
  return SV_CRYPTO_USAGE_BUG;
}
#endif

static int
md_ctx_init (crypto_md_ctx_t **ctx, int md_id)
{
  const EVP_MD *md;

  md = EVP_get_digestbynid (md_id);
  if (!md)
    {
      prlog (PR_ERR, "ERROR: Invalid MD NID\n");
      return SV_CRYPTO_USAGE_BUG;
    }

  *ctx = EVP_MD_CTX_new ();
  if (!*ctx)
    {
      prlog (PR_ERR, "ERROR: failed to allocate memory\n");
      return SV_ALLOCATION_FAILED;
    }

  return !EVP_DigestInit_ex ((EVP_MD_CTX *) *ctx, md, NULL);
}

static int
md_update (crypto_md_ctx_t *ctx, const unsigned char *data, size_t data_len)
{
  /* returns 1 on success and 0 for fail */
  return !EVP_DigestUpdate (ctx, data, data_len);
}

static int
md_finish (crypto_md_ctx_t *ctx, unsigned char *hash)
{
  return !EVP_DigestFinal_ex (ctx, hash, NULL);
}

static void
md_free (crypto_md_ctx_t *ctx)
{
  EVP_MD_CTX_free (ctx);
}

static void
md_hash_free (unsigned char *hash)
{
  OPENSSL_free (hash);
}

static int
md_generate_hash (const unsigned char *data, size_t size, int hash_funct,
                  unsigned char **outHash, size_t *outHashSize)
{
  int rc;
  crypto_md_ctx_t *ctx = NULL;
  size_t hash_len = 0;

  rc = md_ctx_init (&ctx, hash_funct);
  if (rc)
    return rc;

  rc = md_update (ctx, data, size);
  if (rc)
    goto out;

  switch (hash_funct)
    {
      case CRYPTO_MD_SHA1: hash_len = SHA_DIGEST_LENGTH; break;
      case CRYPTO_MD_SHA224: hash_len = SHA224_DIGEST_LENGTH; break;
      case CRYPTO_MD_SHA256: hash_len = SHA256_DIGEST_LENGTH; break;
      case CRYPTO_MD_SHA384: hash_len = SHA384_DIGEST_LENGTH; break;
      case CRYPTO_MD_SHA512: hash_len = SHA512_DIGEST_LENGTH; break;
      default:
        prlog (PR_ERR, "ERROR: Unknown NID (%d)\n", hash_funct);
        rc = SV_CRYPTO_USAGE_BUG;
        goto out;
    }

  *outHash = OPENSSL_malloc (hash_len);
  if (!*outHash)
    {
      prlog (PR_ERR, "ERROR: Failed to allocate data\n");
      rc = SV_ALLOCATION_FAILED;
      goto out;
    }

  rc = md_finish (ctx, *outHash);
  if (rc)
    {
      OPENSSL_free (*outHash);
      *outHash = NULL;
      goto out;
    }

  *outHashSize = hash_len;

out:
  md_free (ctx);
  return rc;
}

md_func_t crypto_md = { .init = md_ctx_init,
                        .update = md_update,
                        .finish = md_finish,
                        .free = md_free,
                        .hash_free = md_hash_free,
                        .generate_hash = md_generate_hash,
                        .error_string = error_string };

pkcs7_func_t crypto_pkcs7 = { .parse_der = pkcs7_parse_der,
                              .md_is_sha256 = pkcs7_md_is_sha256,
                              .get_signing_cert = pkcs7_get_signing_cert,
                              .signed_hash_verify = pkcs7_signed_hash_verify,
                              .error_string = error_string,
#ifdef SECVAR_CRYPTO_WRITE_FUNC
                              .generate_w_signature = pkcs7_generate_w_signature,
                              .generate_w_already_signed_data =
                                      pkcs7_generate_w_already_signed_data,
#endif
                              .free = pkcs7_free };

x509_func_t crypto_x509 = { .get_der_len = x509_get_der_len,
                            .get_tbs_der_len = x509_get_tbs_der_len,
                            .oid_is_pkcs1_sha256 = x509_oid_is_pkcs1_sha256,
                            .get_version = x509_get_version,
                            .is_RSA = x509_is_RSA,
                            .get_pk_bit_len = x509_get_pk_bit_len,
                            .get_sig_len = x509_get_sig_len,
                            .parse_der = x509_parse_der,
                            .error_string = error_string,
                            .is_CA = x509_is_CA,
#ifdef SECVAR_CRYPTO_WRITE_FUNC
                            .get_short_info = x509_get_short_info,
                            .md_is_sha256 = x509_md_is_sha256,
                            .get_long_desc = x509_get_long_desc,
                            .pem_to_der = x509_convert_pem_to_der,
#endif
                            .free = x509_free };

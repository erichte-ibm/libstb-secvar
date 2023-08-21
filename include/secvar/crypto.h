/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#ifndef LIBSTB_SECVAR_CRYPTO_H
#define LIBSTB_SECVAR_CRYPTO_H

#include <stdbool.h>
#include <external/edk2/common.h>

#ifdef SECVAR_CRYPTO_OPENSSL
#include <openssl/obj_mac.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#define OPENSSL_SUCCESS 0
#define CRYPTO_SUCCESS OPENSSL_SUCCESS

#define CRYPTO_MD_SHA1 NID_sha1
#define CRYPTO_MD_SHA224 NID_sha224
#define CRYPTO_MD_SHA256 NID_sha256
#define CRYPTO_MD_SHA384 NID_sha384
#define CRYPTO_MD_SHA512 NID_sha512

typedef PKCS7 crypto_pkcs7_t;
typedef X509 crypto_x509_t;
typedef EVP_MD_CTX crypto_md_ctx_t;
#else
#error Crypto Library not defined! Define SECVAR_CRYPTO_OPENSSL
#endif

/**====================PKCS7 Functions ====================**/
/*
 * free's the memory allocated for a pkcs7 structure
 * @param pkcs7 , a pointer to either a pkcs7 struct
 */
void crypto_pkcs7_free (crypto_pkcs7_t *pkcs7);

/*
 *parses a buffer into a pointer to a pkcs7 struct. struct allocation is done internally to this func, but not dealloc
 *@param buf, buffer of data containg pkcs7 data or pkcs7 signed data
 *@param buflen, length of buf
 *@return if successful, a pointer to a pkcs7 struct. else returns NULL
 *NOTE: if successful (returns not NULL), remember to call crypto_free_pkcs7 to unalloc. 
 */
crypto_pkcs7_t *crypto_pkcs7_parse_der (const unsigned char *buf, const int buflen);

/**====================X509 Functions ====================**/
typedef crypto_x509_t *(*crypto_x509_parse_der_cert) (const unsigned char *, size_t);
typedef void (*crypto_str_error) (int, char *, size_t);

/*
 * checks if the x509 is a CA certificate
 * @param x509 , reference to the x509
 * @return true if CA, otherwise false
 */
bool crypto_x509_is_CA (crypto_x509_t *x509);

/*
 * gets the DER length of the x509 structure
 * @param x509 , reference to the x509
 * @return length in bytes or negative value on error
 */
int crypto_x509_get_der_len (crypto_x509_t *x509);

/*
 * gets the length of the to-be-signed buffer
 * @param x509 , reference to the x509
 * @return length in bytes or negative value on error
 */
int crypto_x509_get_tbs_der_len (crypto_x509_t *x509);

/*
 * gets the length of the signature
 * @param x509 , reference to the x509
 * @return length in bytes or negative value on error
 */
int crypto_x509_get_sig_len (crypto_x509_t *x509);

/*
 * gets the length in bits of the signature
 * @param x509, reference to the x509
 * @return length in bits or negative value on error
 */
int crypto_x509_get_pk_bit_len (crypto_x509_t *x509);

int crypto_x509_get_version (crypto_x509_t *x509);

bool crypto_x509_is_RSA (crypto_x509_t *x509);

/*
 * returns CRYPTO_SUCCESS if oid is sha256
 */
int crypto_x509_oid_is_pkcs1_sha256(crypto_x509_t *x509);

/*
 * unallocates x509 struct and memory
 * @param x509 ,  a pointer to an x509 struct
 */
void crypto_x509_free (crypto_x509_t *x509);

/**====================General Functions ====================**/

/*
 * accepts an error code from crypto backend and returns a string describing it
 * @param rc , the error code
 * @param out_str , an already allocated string, will be filled with string describing the error code
 * @out_max_len , the number of bytes allocated to out_str
 */
void crypto_strerror (int rc, char *out_str, size_t out_max_len);

#ifdef SECVAR_CRYPTO_WRITE_FUNC
typedef void (*crypto_x509_short_info) (crypto_x509_t *, char *, size_t);
typedef int (*convert_pem_to_der) (const unsigned char *, size_t, unsigned char **, size_t *);
typedef int (*crypto_x509_cert_long_desc) (char *, size_t, const char *, crypto_x509_t *);
typedef int (*crypto_x509_is_md_sha256) (crypto_x509_t *);
#endif

/* MD HASH */
typedef int (*crypto_md_ctx_init) (crypto_md_ctx_t **, int);
typedef int (*crypto_md_update) (crypto_md_ctx_t *, const unsigned char *, size_t);
typedef int (*crypto_md_finish) (crypto_md_ctx_t *, unsigned char *);
typedef void (*crypto_md_free) (crypto_md_ctx_t *);
typedef void (*crypto_md_hash_free) (unsigned char *);
typedef int (*crypto_md_generate_hash) (const unsigned char *, size_t, int, unsigned char **, size_t *);

/* PKCS7 */
typedef int (*crypto_pkcs7_md_sha256) (crypto_pkcs7_t *);
typedef crypto_x509_t *(*crypto_pkcs7_get_signing_cert) (crypto_pkcs7_t *, int);
typedef int (*crypto_pkcs7_signed_hash_verify) (crypto_pkcs7_t *, crypto_x509_t *,
                                                unsigned char *, int);
#ifdef SECVAR_CRYPTO_WRITE_FUNC
typedef int (*crypto_pkcs7_generate_w_signature) (unsigned char **, size_t *, const unsigned char *,
                                                  size_t, const char **, const char **, int, int);
typedef int (*crypto_pkcs7_generate_w_already_signed_data) (unsigned char **, size_t *,
                                                            const unsigned char *, size_t,
                                                            const char **, const char **,
                                                            int, int);
#endif

struct pkcs7_func
{
  crypto_pkcs7_md_sha256 md_is_sha256;
  crypto_pkcs7_signed_hash_verify signed_hash_verify;
  crypto_pkcs7_get_signing_cert get_signing_cert;
#ifdef SECVAR_CRYPTO_WRITE_FUNC
  crypto_pkcs7_generate_w_signature generate_w_signature;
  crypto_pkcs7_generate_w_already_signed_data generate_w_already_signed_data;
#endif
};

typedef struct pkcs7_func pkcs7_func_t;

struct md_func
{
  crypto_md_ctx_init init;
  crypto_md_update update;
  crypto_md_finish finish;
  crypto_md_free free;
  crypto_md_hash_free hash_free;
  crypto_md_generate_hash generate_hash;
};

typedef struct md_func md_func_t;

struct x509_func
{
  crypto_x509_parse_der_cert parse_der;
#ifdef SECVAR_CRYPTO_WRITE_FUNC
  crypto_x509_short_info get_short_info;
  crypto_x509_cert_long_desc get_long_desc;
  crypto_x509_is_md_sha256 md_is_sha256;
  convert_pem_to_der pem_to_der;
#endif
};

typedef struct x509_func x509_func_t;

/* MD HASH */
extern md_func_t crypto_md;
/* PKCS7 */
extern pkcs7_func_t crypto_pkcs7;
/* X509 */
extern x509_func_t crypto_x509;

typedef int (*generate_hash) (const uint8_t *, const size_t, const int, uint8_t **, size_t *);
typedef int (*get_pkcs7_cert) (const uint8_t *, size_t, crypto_pkcs7_t **);
typedef int (*validate_x509_cert) (crypto_x509_t *);
typedef int (*get_x509_cer) (const uint8_t *, size_t, crypto_x509_t **);
typedef int (*verify_pkcs7) (crypto_pkcs7_t *, crypto_x509_t *, unsigned char *, int);
typedef int (*pkcs7_md) (crypto_pkcs7_t *);

#ifdef SECVAR_CRYPTO_WRITE_FUNC
typedef int (*generate_pkcs7_sig) (uint8_t *, size_t, uint8_t **, uint8_t **, size_t, uint8_t **, size_t *);
typedef int (*generate_pkcs7) (uint8_t *, size_t, uint8_t **, uint8_t **, size_t, uint8_t **, size_t *);
typedef int (*read_x509_cert) (const char *, crypto_x509_t *, size_t, char **);
typedef int (*der_from_pem) (const uint8_t *, size_t, uint8_t **, size_t *);
typedef int (*get_signing_cert) (crypto_pkcs7_t *, int, crypto_x509_t **);
#endif

struct crypto
{
#ifdef SECVAR_CRYPTO_WRITE_FUNC
  generate_pkcs7_sig generate_pkcs7_signature;
  generate_pkcs7 generate_pkcs7_from_signed_data;
  read_x509_cert read_x509_certificate_info;
  der_from_pem get_der_from_pem;
  get_signing_cert get_signing_cert_from_pkcs7;
#endif
  generate_hash generate_md_hash;
  get_pkcs7_cert get_pkcs7_certificate;
  validate_x509_cert validate_x509_certificate;
  get_x509_cer get_x509_certificate;
  verify_pkcs7 verify_pkcs7_signature;
  pkcs7_md pkcs7_md_is_sha256;
};

typedef struct crypto crypto_func_t;

#ifdef SECVAR_CRYPTO_WRITE_FUNC
struct hash_func
{
  char name[8];
  size_t size;
  int crypto_md_funct;
  uuid_t const *guid;
};

typedef struct hash_func hash_func_t;

extern hash_func_t hash_functions[5];
extern hash_func_t x509_hash_functions[3];
#endif
extern crypto_func_t crypto;

#endif

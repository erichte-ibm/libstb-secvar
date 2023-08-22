/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#ifndef LIBSTB_SECVAR_CRYPTO_H
#define LIBSTB_SECVAR_CRYPTO_H

#include <stdbool.h>

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

/*
 * checks the pkcs7 struct for using SHA256 as the message digest
 * @param pkcs7 , a pointer to either a pkcs7 struct
 * @return CRYPTO_SUCCESS if message digest is SHA256 else return errno
 */
int crypto_pkcs7_md_is_sha256 (crypto_pkcs7_t *pkcs7);

#ifdef SECVAR_CRYPTO_WRITE_FUNC
/*
 * returns one signing ceritficate from the PKKCS7 signing certificate chain
 * @param pkcs7 ,  a pointer to a pkcs7 struct
 * @param cert_num , the index (starts at 0) of the signing certificate to retrieve
 * @return a pointer to an X509 struct
 * NOTE: The returned pointer need not be freed, since it is a reference to memory in pkcs7
 */
crypto_x509_t *crypto_pkcs7_get_signing_cert (crypto_pkcs7_t *pkcs7, int cert_num);

/*
 * generates a PKCS7 and create signature with private and public keys
 * @param pkcs7, the resulting PKCS7 DER buff, newData not appended, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 * @param pkcs7_size, the length of pkcs7
 * @param new_data, data to be added to be used in digest
 * @param new_data_size , length of newData
 * @param crt_files, array of file paths to public keys to sign with(PEM)
 * @param key_files, array of file paths to private keys to sign with
 * @param key_pairs, array length of key/crtFiles
 * @param hash_funct, hash function to use in digest, see crypto_hash_funct for values
 * @return CRYPTO_SUCCESS or err number
 */
int crypto_pkcs7_generate_w_signature (unsigned char **pkcs7, size_t *pkcs7_size,
                            const unsigned char *new_data, size_t new_data_size,
                            const char **crt_files, const char **key_files,
                            int key_pairs, int hash_funct);

/*
 * generates a PKCS7 with given signed data
 * @param pkcs7, the resulting PKCS7, newData not appended, NOTE: REMEMBER TO UNALLOC THIS MEMORY
 * @param pkcs7Size, the length of pkcs7
 * @param newData, data to be added to be used in digest
 * @param dataSize , length of newData
 * @param crtFiles, array of file paths to public keys that were used in signing with(PEM)
 * @param sigFiles, array of file paths to raw signed data files
 * @param keyPairs, array length of crt/signatures
 * @param hashFunct, hash function to use in digest, see crypto_hash_funct for values
 * @return CRYPTO_SUCCESS or err number
 * NOTE: This is not supported on openssl builds
 */
int crypto_pkcs7_generate_w_already_signed_data (unsigned char **pkcs7, size_t *pkcs7_size,
                                      const unsigned char *new_data, size_t new_data_size,
                                      const char **crt_files, const char **sig_files,
                                      int key_pairs, int hash_funct);
#endif

/*
 * determines if signed data in pkcs7 is correctly signed by x509 by signing the hash with the
 * pk and comparing the resulting signature with that in the pkcs7
 * @param pkcs7 , a pointer to a pkcs7 struct
 * @param x509 , a pointer to an x509 struct
 * @param hash , the expected hash
 * @param hash_len , the length of expected hash (ex: SHA256 = 32), if 0 then asssumptions are made based on md in pkcs7
 * @return CRYPTO_SUCCESS or error number if resulting hashes are not equal
 */
int crypto_pkcs7_signed_hash_verify (crypto_pkcs7_t *pkcs7, crypto_x509_t *x509,
                                     unsigned char *hash, int hash_len);

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

/*
 *parses a buffer into a pointer to an x509 struct. struct allocation is done internally to this func, but not dealloc
 *@param buf, buffer of data containing x509 data in DER
 *@param buflen, length of buf
 *@return if successful, a pointer to an x509 struct. else returns NULL
 *NOTE: if successful (returns not NULL), remember to call crypto_x509_free to unalloc.
 */
crypto_x509_t *crypto_x509_parse_der (const unsigned char *data, size_t data_len);

#ifdef SECVAR_CRYPTO_WRITE_FUNC
/* return CRYPTO_SUCCESS if md of cert is sha256 */
int crypto_x509_md_is_sha256 (crypto_x509_t *x509);

/*
 * returns a short string describing the x509 message digest and encryption algorithms
 * @param x509, a pointer to an x509 struct
 * @param short_desc ,  already alloc'd pointer to output string
 * @param max_len   , number of bytes allocated to short_desc arg
 */
void crypto_x509_get_short_info (crypto_x509_t *x509, char *short_desc, size_t max_len);

/*
 * parses the x509 struct into a human readable informational string
 * @param x509_info , already alloc-d pointer to output string
 * @param max_len , number of bytes allocated to x509_info
 * @param delim  , eachline will start with this, usually indent, when using openssl, the length of this value is the number of 8 spaced tabs
 * @param x509 ,  a pointer to  an x509 struct
 * @return number of bytes written to x509_info
 */
int crypto_x509_get_long_desc (char *x509_info, size_t max_len, const char *delim, crypto_x509_t *x509);
#endif

/**====================Hashing Functions ====================**/

/*
 * Initializes and returns hashing context for the hashing function identified
 * @param ctx , the returned hashing context
 * @param md_id , the id of the hahsing function see above for possible values (CRYPTO_MD_xxx )
 * @return CRYPTO_SUCCESS or err if the digest context setup failed
 */
int crypto_md_ctx_init (crypto_md_ctx_t **ctx, int md_id);

/*
 * can be repeatedly called to add data to be hashed by ctx
 * @param ctx , a pointer to either a hashing context
 * @param data , data to be hashed
 * @param data_len , length of data to be hashed
 * @return CRYPTO_SUCCESS or err if additional data could not be added to context
 */
int crypto_md_update (crypto_md_ctx_t *ctx, const unsigned char *data, size_t data_len);

/*
 * runs the hash over the supplied data (given with crypto_md_update) and returns it in hash
 * @param  ctx , a pointer to a hashing context
 * @param hash, an allocated data blob where the returned hash will be stored
 * @return CRYPTO_SUCCESS or err if the hash generation was successful
 */
int crypto_md_finish (crypto_md_ctx_t *ctx, unsigned char *hash);

/*
 * frees the memory allocated for the hashing context
 * @param ctx , a pointer to a hashing context
 */
void crypto_md_free (crypto_md_ctx_t *ctx);

/*
 * given a data buffer, generate the desired hash
 * @param data, data to be hashed
 * @param size , length of buff
 * @param hash_funct, crypto_md_funct, message digest type
 * @param out_hash , the resulting hash, currently unalloc'd NOTE: REMEMBER TO UNALLOC THIS MEMORY
 * @param out_hash_size, should be alg->size
 * @return CRYPTO_SUCCESS or err number
 * NOTE: out_hash is allocated inside this function and must be unallocated sometime after calling
 */
int crypto_md_generate_hash (const unsigned char *data, size_t size, int hash_funct,
                  unsigned char **out_hash, size_t *out_hash_size);

/**====================General Functions ====================**/

/*
 * accepts an error code from crypto backend and returns a string describing it
 * @param rc , the error code
 * @param out_str , an already allocated string, will be filled with string describing the error code
 * @out_max_len , the number of bytes allocated to out_str
 */
void crypto_strerror (int rc, char *out_str, size_t out_max_len);

#ifdef SECVAR_CRYPTO_WRITE_FUNC
/*
 * attempts to convert PEM data buffer into DER data buffer
 * @param input , PEM data buffer
 * @param ilen , length of input data
 * @param output , pointer to output DER data, not yet allocated
 * @param olen , pointer to length of output data
 * @return CRYPTO_SUCCESS or errno if conversion failed
 * Note: Remember to unallocate the output data!
 */
int crypto_convert_pem_to_der (const unsigned char *input, size_t ilen, unsigned char **output, size_t *olen);
#endif

typedef int (*get_pkcs7_cert) (const uint8_t *, size_t, crypto_pkcs7_t **);
typedef int (*validate_x509_cert) (crypto_x509_t *);

struct crypto
{
  get_pkcs7_cert get_pkcs7_certificate;
  validate_x509_cert validate_x509_certificate;
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
#endif
extern crypto_func_t crypto;

#endif

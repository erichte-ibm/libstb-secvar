/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#ifndef __LIBSTB_SECVAR_ERRORS_H
#define __LIBSTB_SECVAR_ERRORS_H

#define APPEND_HEADER_LEN 8

enum _sv_errors
{
  SV_SUCCESS = 0,
  SV_BUF_INSUFFICIENT_DATA = 1, /* a buffer is too small for the data it is supposed to contain */
  SV_ESL_SIZE_INVALID,          /* a size field in the ESL is invalid. */
  SV_ESL_WRONG_TYPE,            /* an ESL didn't contain a SignatureType we expect */
  SV_AUTH_INVALID_FIXED_VALUE,  /* e.g. timestamp with some non-zeros where they aren't supposed to be, w_cert_type != 0xef1 */
  SV_AUTH_SIZE_INVALID,         /* a size field in the auth structure is invalid */
  SV_AUTH_UNSUPPORTED_REVISION, /* w_revision != 0x0200 */
  SV_OUT_BUF_TOO_SMALL,         /* output buffer too small for the data */
  SV_TOO_MUCH_DATA,             /* e.g. ESL doesn't fit in 32-bit size */
  SV_TIMESTAMP_IN_PAST,         /* attempted to apply an update from the past TODO RENAME NOT_IN_FUTURE */
  SV_ALLOCATION_FAILED,         /* libstb_zalloc returned NULL */

  /* crypto */
  SV_PKCS7_PARSE_ERROR = 0x100, /* failed to parse a PKCS#7 message from DER. */
  SV_PKCS7_ERROR,               /* the message parsed but we couldn't extract some key part of it */
  SV_UNEXPECTED_PKCS7_ALGO,     /* a PKCS7 signature is not made with SHA-256 */
  SV_X509_PARSE_ERROR,          /* failed to parse an x509 cert from DER */
  SV_X509_ERROR,                /* the certificate parsed but we couldn't extract some key part from it, or it is not v3 */
  SV_UNEXPECTED_CERT_ALGO,      /* a cert we were given to verify a signature is not RSA */
  SV_UNEXPECTED_CERT_SIZE,      /* as above, but the cert is not [RSA-]2048/4096 */
  SV_UNEXPECTED_CRYPTO_ERROR,   /* something unspecific went wrong in cryptoland */
  SV_CRYPTO_USAGE_BUG,          /* the programmer called a crypto function in a way they shouldn't have done */
  SV_FAILED_TO_VERIFY_SIGNATURE,/* no trusted key verified the signature */

  /* pseries specific */
  /*
   * label size is odd or there is an embedded u16 nul. We don't strictly require UCS-2,
   * but that would be wise
   */
  SV_LABEL_IS_NOT_WIDE_CHARACTERS = 0x200,
  SV_UNPACK_ERROR,              /* when unpacking a signed variable, it was too small somehow */
  SV_UNPACK_VERSION_ERROR,      /* unpacking a non-v0 signed var */
  SV_CANNOT_APPEND_TO_PK,       /* you tried to append to PK. Don't do that. */
  SV_DELETE_EVERYTHING,         /* A signed PK update + allow unauth PK update + WIPE_SB_MAGIC was sent */
  SV_INVALID_PK_UPDATE,         /* you tried to update the PK but it wasn't an ESL containing a single RSA-2048/4096 cert */
  /*
   * you tried to update the KEK but the resultant variable it wasn't either empty or
   * a set of ESLs containing RSA-2048/4096 certs.
   */
  SV_INVALID_KEK_UPDATE,
  SV_INVALID_TRUSTEDCADB_UPDATE,

#ifdef SECVAR_CRYPTO_WRITE_FUNC
  /* currently unused, untested and broken auth file write support */
  SV_INVALID_FILE = 0xff00,
#endif
};

typedef enum _sv_errors sv_err_t;

#endif

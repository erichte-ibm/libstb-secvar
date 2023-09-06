/*
 * Copyright (c) 2006 - 2015, Intel Corporation. All rights reserved. This
 * program and the accompanying materials are licensed and made available
 * under the terms and conditions of the 2-Clause BSD License which
 * accompanies this distribution.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * https://github.com/tianocore/edk2-staging (edk2-staging repo of tianocore),
 * these are the files under it, and here's the copyright and license.
 *
 * MdePkg/Include/Guid/GlobalVariable.h
 * MdePkg/Include/Guid/WinCertificate.h
 * MdePkg/Include/Uefi/UefiMultiPhase.h
 * MdePkg/Include/Uefi/UefiBaseType.h
 * MdePkg/Include/Guid/ImageAuthentication.h
 *
 *
 * Copyright 2023 IBM Corp.
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef __LIBSTB_SECVAR_COMMON_H
#define __LIBSTB_SECVAR_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"
#include "ccan/endian/endian.h"

#define MAX_HASH_SIZE 32
#define UUID_SIZE 16
#define SV_CERT_TYPE_PKCS_SIGNED_DATA	0x0002
/*
 * Attributes of Authenticated Variable
 * It is derived from EFI_VARIABLE_APPEND_WRITE
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Uefi/UefiMultiPhase.h
 */
#define SV_VARIABLE_APPEND_WRITE 0x00000040
/*
 * It is derived from EFI_CERT_TYPE_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/WinCertificate.h
 */
#define AUTH_CERT_TYPE_GUID 0x0ef1
#define SV_PACKED __attribute__ ((packed))

/* The structure of a UUID.*/
typedef struct
{
  uint8_t b[UUID_SIZE];
} uuid_t;

/*
 * It is derived from EFI_GLOBAL_VARIABLE_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/GlobalVariable.h
 */
static const uuid_t SV_GLOBAL_VARIABLE_GUID = { { 0x61, 0xDF, 0xe4, 0x8b, 0xca,
                                                  0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00,
                                                  0xe0, 0x98, 0x03, 0x2b, 0x8c } };

/*
 * It is derived from EFI_IMAGE_SECURITY_DATABASE_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t SV_IMAGE_SECURITY_DATABASE_GUID = { { 0xcb, 0xb2, 0x19, 0xd7,
                                                          0x3a, 0x3d, 0x96, 0x45,
                                                          0xa3, 0xbc, 0xda, 0xd0,
                                                          0x0e, 0x67, 0x65, 0x6f } };

/*
 * It is derived from EFI_CERT_TYPE_PKCS7_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t AUTH_CERT_TYPE_PKCS7_GUID = { { 0x9d, 0xd2, 0xaf, 0x4a, 0xdf,
                                                    0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34,
                                                    0x7d, 0x37, 0x56, 0x65, 0xa7 } };

/*
 * It is derived from EFI_CERT_X509_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_X509_GUID = { { 0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94,
                                             0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15,
                                             0x5c, 0x2b, 0xf0, 0x72 } };

#ifdef SECVAR_CRYPTO_WRITE_FUNC
/*
 * It is derived from EFI_CERT_SHA1_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_SHA1_GUID = { { 0x12, 0xa5, 0x6c, 0x82, 0x10, 0xcf,
                                             0xc9, 0x4a, 0xb1, 0x87, 0xbe, 0x01,
                                             0x49, 0x66, 0x31, 0xbd } };

/*
 * It is derived from EFI_CERT_SHA224_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_SHA224_GUID = { { 0x33, 0x52, 0x6e, 0x0b, 0x5c, 0xa6,
                                               0xc9, 0x44, 0x94, 0x07, 0xd9, 0xab,
                                               0x83, 0xbf, 0xc8, 0xbd } };

/*
 * It is derived from EFI_CERT_SHA256_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_SHA256_GUID = { { 0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50,
                                               0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9,
                                               0x36, 0x93, 0x43, 0x28 } };

/*
 * It is derived from EFI_CERT_SHA384_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_SHA384_GUID = { { 0x07, 0x53, 0x3e, 0xff, 0xd0, 0x9f,
                                               0xc9, 0x48, 0x85, 0xf1, 0x8a, 0xd5,
                                               0x6c, 0x70, 0x1e, 0x01 } };

/*
 * It is derived from EFI_CERT_SHA512_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_SHA512_GUID = { { 0xae, 0x0f, 0x3e, 0x09, 0xc4, 0xa6,
                                               0x50, 0x4f, 0x9f, 0x1b, 0xd4, 0x1e,
                                               0x2b, 0x89, 0xc1, 0x9a } };

/*
 * It is derived from EFI_CERT_RSA2048_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_RSA2048_GUID = { { 0xe8, 0x66, 0x57, 0x3c, 0x9c, 0x26,
                                                0x34, 0x4e, 0xaa, 0x14, 0xed, 0x77,
                                                0x6e, 0x85, 0xb3, 0xb6 } };

/*
 * It is derived from EFI_CERT_X509_SHA256_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_X509_SHA256_GUID = { { 0x92, 0xa4, 0xd2, 0x3b, 0xc0,
                                                    0x96, 0x79, 0x40, 0xb4, 0x20,
                                                    0xfc, 0xf9, 0x8e, 0xf1, 0x03,
                                                    0xed } };

/*
 * It is derived from EFI_CERT_X509_SHA384_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_X509_SHA384_GUID = { { 0x6e, 0x87, 0x76, 0x70, 0xc2, 0x80,
                                                    0xe6, 0x4e, 0xaa, 0xd2, 0x28, 0xb3,
                                                    0x49, 0xa6, 0x86, 0x5b } };

/*
 * It is derived from EFI_CERT_X509_SHA512_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
static const uuid_t PKS_CERT_X509_SHA512_GUID = { { 0x63, 0xbf, 0x6d, 0x44, 0x02, 0x25,
                                                    0xda, 0x4c, 0xbc, 0xfa, 0x24, 0x65,
                                                    0xd2, 0xb0, 0xfe, 0x9d } };

static const uuid_t PKS_CERT_SBAT_GUID = { { 0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0,
                                             0x0, 0x43, 0xab, 0xb6, 0x3d, 0xd8,
                                             0x10, 0xdd, 0x8b, 0x23 } };
#endif

/*
 * It is derived from EFI_SIGNATURE_DATA
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
struct sv_esd
{
  uuid_t signature_owner;  /* An identifier which identifies the agent which added
                              the signature to the list */
  uint8_t signature_data[];/* The format of the signature is defined by the SignatureType. */
} SV_PACKED;

/*
 * It is derived from EFI_SIGNATURE_LIST
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/ImageAuthentication.h
 */
struct sv_esl
{
  uuid_t signature_type;         /* Type of the signature. */
  uint32_t signature_list_size;  /* Total size of the signature list, including this header */
  uint32_t signature_header_size;/* Size of the signature header which precedes the array
                                    of signatures */
  uint32_t signature_size;       /* Size of each signature.*/
} SV_PACKED;

typedef struct sv_esd sv_esd_t;
typedef struct sv_esl sv_esl_t;

/*
 * It is derived from WIN_CERTIFICATE
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/WinCertificate.h
 */
struct auth_header
{
  leint32_t da_length;          /* The length of the entire certificate */
  leint16_t a_revision;         /* The revision level of the AUTH_CERTIFICATE structure */
  leint16_t a_certificate_type; /* The certificate type */
} SV_PACKED;

typedef struct auth_header auth_header_t;

/*
 * Certificate which encapsulates a GUID-specific digital signature
 * It is derived from WIN_CERTIFICATE_UEFI_GUID
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Guid/WinCertificate.h
 */
struct auth_cert
{
  auth_header_t hdr;    /* This is the standard auth_certificate header,
                           where a_certificate_type is set to AUTH_CERT_TYPE_GUID */
  uuid_t cert_type;     /* This is the unique id which determines the format of the cert_data */
  uint8_t cert_data[0]; /* the certificate data */
} SV_PACKED;

typedef struct auth_cert auth_cert_t;

/*
 * Timestamp Abstraction:
 *   Year:       1900 - 9999
 *   Month:      1 - 12
 *   Day:        1 - 31
 *   Hour:       0 - 23
 *   Minute:     0 - 59
 *   Second:     0 - 59
 *   Nanosecond: 0 - 999,999,999
 *   TimeZone:   -1440 to 1440 or 2047
 *
 * It is derived from EFI_TIME
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Uefi/UefiBaseType.h
 */
struct sv_timestamp
{
  leint16_t year;
  uint8_t month;
  uint8_t day;
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
  uint8_t pad1;
  leint32_t nanosecond;
  leint16_t timezone;
  uint8_t daylight;
  uint8_t pad2;
} SV_PACKED;

typedef struct sv_timestamp timestamp_t;

/*
 * It is derived from EFI_VARIABLE_AUTHENTICATION_2
 * https://github.com/tianocore/edk2-staging/blob/master/MdePkg/Include/Uefi/UefiMultiPhase.h
 */
struct auth_info
{
  timestamp_t timestamp; /* For the TimeStamp value, components Pad1, Nanosecond, TimeZone,
                            Daylight and Pad2 shall be set to 0 */
  auth_cert_t auth_cert; /* Only a CertType of  AUTH_CERT_TYPE_PKCS7_GUID is accepted */
} SV_PACKED;

typedef struct auth_info auth_info_t;

enum sv_variable_update_flags
{
  SV_VARIABLE_UPDATE_NO_FLAGS = 0,
  SV_VARIABLE_UPDATE_SKIP_VERIFICATION = 1 << 0,
  SV_AUTH_VERIFIED_BY_PK = 1 << 1,
  SV_AUTH_VERIFIED_BY_KEK = 1 << 2,
};

typedef enum sv_variable_update_flags sv_flag_t;

struct auth_database
{
  const uint8_t *pk;  /* Platform Key database */
  const uint8_t *kek; /* Key Exchange Key database */
  size_t pk_size;     /* size of Platform Key database */
  size_t kek_size;    /* size of Key Exchange Key database */
};

typedef struct auth_database auth_db_t;

struct update_request
{
  bool allow_unauthenticated;  /* allow an unauthenticated PK update */
  bool append_update;          /* append update flag*/
  const uint8_t *label;        /* secure boot variable name */
  size_t label_size;           /* size of secure boot variable name */
  const uint8_t *update_data;  /* auth message from user */
  const uint8_t *current_data; /* current secure boot variable data */
  size_t update_data_size;     /* size of auth message */
  size_t current_data_size;    /* size of current secure boot variable data */
  auth_db_t auth_db;           /* PK and KEK database */
};

struct auth_data
{
  sv_flag_t flag;                 /* the signature validation flag */
  const uuid_t *vendor;           /* GUID of the variable update */
  uint32_t attributes;            /* Update variable attributes in CPU endian */
  const uint16_t *name;           /* secure boot variable name */
  const uint8_t *auth_msg;        /* auth message from user */
  size_t auth_msg_size;           /* size of auth message */
  const uint8_t *current_esl_data;/* current variable esl data */
  size_t current_esl_data_size;   /* size of current variable esl data */
  timestamp_t *current_time;      /* current variable timestamp */
  auth_db_t auth_db;              /* PK and KEK database */
};

typedef struct auth_data auth_data_t;
typedef struct update_request update_req_t;

#ifdef SECVAR_CRYPTO_WRITE_FUNC
static const char defined_sb_variables [9] [12] = { "PK", "KEK", "db", "dbx", "grubdb",
                                                       "grubdbx", "sbat", "moduledb",
                                                       "trustedcadb"
                                                     };
static const int defined_sb_variable_len = 9;
#endif

#endif

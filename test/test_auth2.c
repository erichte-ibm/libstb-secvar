/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include "secvar/authentication_2.h"
#include "secvar/pseries.h"
#include <stddef.h>
#include "data/pk_auth.h"
#include "data/delete_pk_sbvs_auth.h"
#include "data/delete_pk_sesl_auth.h"
#include "data/svc_dbx_by_KEK_auth.h"
#include <stdio.h>

__attribute__((unused)) static const uint16_t *DBX_NAME = (const uint16_t *)"d\0b\0x\0\0\0";

int
main (int argc, char **argv)
{
  auth_data_t auth_data = { 0 };
  const uint8_t *cert, *data;
  size_t cert_size, data_size;
  sv_err_t rc;
  timestamp_t timestamp;
  uint8_t hash[MAX_HASH_SIZE] = { 0 };

  printf ("\n5 test cases for unpacking of authenticated variable\n\n");

  auth_data.auth_msg = pk_auth;
  auth_data.auth_msg_size = pk_auth_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert, &cert_size,
                                      &data, &data_size);
  if (rc == SV_SUCCESS && (cert_size > 0 && cert_size < pk_auth_len) &&
      data_size == 857 && (data == pk_auth + pk_auth_len - data_size) &&
      le16_to_cpu (timestamp.year) == 2022)
    printf ("Test case-1 : PASSED\n");
  else
    {
      printf ("Test case-1 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  auth_data.auth_msg = delete_pk_sbvs_auth;
  auth_data.auth_msg_size = delete_pk_sbvs_auth_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert, &cert_size,
                                      &data, &data_size);
  if (rc == SV_SUCCESS && (cert_size > 0 && cert_size < delete_pk_sbvs_auth_len) &&
      data_size == 0 && (le16_to_cpu (timestamp.year) == 2022 - 1900))
    printf ("Test case-2 : PASSED\n");
  else
    {
      printf ("Test case-2 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  auth_data.auth_msg = delete_pk_sesl_auth;
  auth_data.auth_msg_size = delete_pk_sesl_auth_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert, &cert_size,
                                      &data, &data_size);
  if (rc == SV_SUCCESS && (cert_size > 0 && cert_size < delete_pk_sesl_auth_len) &&
      data_size == 0 && (le16_to_cpu (timestamp.year) == 2022))
    printf ("Test case-3 : PASSED\n");
  else
    {
      printf ("Test case-3 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  auth_data.auth_msg = svc_dbx_by_KEK_auth;
  auth_data.auth_msg_size = svc_dbx_by_KEK_auth_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert, &cert_size,
                                      &data, &data_size);
  if (rc == SV_SUCCESS && (cert_size > 0 && cert_size < svc_dbx_by_KEK_auth_len) &&
      (data_size > 0 && data_size < svc_dbx_by_KEK_auth_len) &&
      (le16_to_cpu (timestamp.year) == 2020))
    printf ("Test case-4 : PASSED\n");
  else
    {
      printf ("Test case-4 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  auth_data.name = (uint16_t *) DBX_NAME;
  auth_data.vendor = (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;
  auth_data.attributes = SECVAR_ATTRIBUTES;

  rc = construct_auth2_hash (&auth_data, &timestamp, data, data_size, hash);
  /* 
   * 6b:bb:47:0b:52:59:f6:9e:02:07:94:39:93:ea:4b:25:8b:51:0e:df:c5:1f:
   * a5:bd:ba:df:9f:ba:92:4e:4b:82
   */
  if (rc == SV_SUCCESS && hash != NULL && hash[0] == 0x6b && hash[1] == 0xbb &&
      hash[30] == 0x4b && hash[31] == 0x82)
    printf ("Test case-5 : PASSED\n");
  else
    {
      printf ("Test case-5 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  return 0;
}

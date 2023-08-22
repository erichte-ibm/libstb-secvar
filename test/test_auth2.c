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
#include "test_utils.h"

__attribute__((unused)) static const uint16_t *DBX_NAME = (const uint16_t *)"d\0b\0x\0\0\0";

int
main (int argc, char **argv)
{
  auth_data_t auth_data = { 0 };
  const uint8_t *cert, *data;
  size_t cert_size, data_size;
  sv_err_t rc;
  timestamp_t timestamp;
  uint8_t *hash = NULL;

  printf ("testing authenticated variables unpack...");

  auth_data.auth_msg = pk_auth;
  auth_data.auth_msg_size = pk_auth_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert, &cert_size,
                                      &data, &data_size);

  assert_rc (SV_SUCCESS);
  assert (cert_size > 0);
  assert (cert_size < pk_auth_len);
  assert (data_size == 857);
  assert (data == pk_auth + pk_auth_len - data_size);
  assert (le16_to_cpu(timestamp.year) == 2022);

  auth_data.auth_msg = delete_pk_sbvs_auth;
  auth_data.auth_msg_size = delete_pk_sbvs_auth_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert, &cert_size,
                                      &data, &data_size);

  assert_rc (SV_SUCCESS);
  assert (cert_size < delete_pk_sbvs_auth_len);
  assert (data_size == 0);
  assert (le16_to_cpu (timestamp.year) == 2022 - 1900);

  auth_data.auth_msg = delete_pk_sesl_auth;
  auth_data.auth_msg_size = delete_pk_sesl_auth_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert, &cert_size,
                                      &data, &data_size);

  assert_rc (SV_SUCCESS);
  assert (cert_size > 0);
  assert (cert_size < delete_pk_sesl_auth_len);
  assert (data_size == 0);
  assert (le16_to_cpu (timestamp.year) == 2022);

  auth_data.auth_msg = svc_dbx_by_KEK_auth;
  auth_data.auth_msg_size = svc_dbx_by_KEK_auth_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert, &cert_size,
                                      &data, &data_size);

  assert_rc (SV_SUCCESS);
  assert (cert_size > 0);
  assert (cert_size < svc_dbx_by_KEK_auth_len);
  assert (data_size > 0);
  assert (data_size < svc_dbx_by_KEK_auth_len);
  assert (le16_to_cpu (timestamp.year) == 2020);

  auth_data.name = (uint16_t *) DBX_NAME;
  auth_data.vendor = (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;
  auth_data.attributes = SECVAR_ATTRIBUTES;

  rc = construct_auth2_hash (&auth_data, &timestamp, data, data_size, &hash);
  /* 
   * 6b:bb:47:0b:52:59:f6:9e:02:07:94:39:93:ea:4b:25:8b:51:0e:df:c5:1f:
   * a5:bd:ba:df:9f:ba:92:4e:4b:82
   */
  assert_rc (SV_SUCCESS);
  assert (hash[0] == 0x6b);
  assert (hash[1] == 0xbb);
  assert (hash[30] == 0x4b);
  assert (hash[31] == 0x82);

  free (hash);
  printf("PASS\n");

  return 0;
}

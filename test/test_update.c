/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include "secvar/pseries.h"
#include "secvar/authentication_2.h"
#include "secvar/util.h"
#include <stddef.h>
#include "data/pk_auth.h"
#include "data/delete_pk_sbvs_auth.h"
#include "data/delete_pk_sesl_auth.h"
#include "data/one_esl.h"
#include "data/kek_esl.h"
#include "data/svc_db_by_PK_auth.h"
#include "data/svc_dbx_by_KEK_auth.h"
#include "libstb-secvar-errors.h"
#include <stdio.h>
#include <assert.h>

static const uint16_t *PK_NAME = (const uint16_t *)"P\0K\0\0\0";
static const uint16_t *DB_NAME = (const uint16_t *)"d\0b\0\0\0";
static const uint16_t *DBX_NAME = (const uint16_t *)"d\0b\0x\0\0\0";

int
main (int argc, char **argv)
{
  auth_data_t auth_data = { 0 };
  const uint8_t *cert, *data;
  size_t cert_size, data_size;
  sv_err_t rc;
  timestamp_t timestamp, new_timestamp, new_timestamp2;
  uint8_t *new_data, *new_data2;
  size_t new_data_size, new_data2_size;
  sv_flag_t verified_flag;

  printf ("\n9 test Cases for apply variable update\n\n");

  auth_data.auth_msg = svc_db_by_PK_auth;
  auth_data.auth_msg_size = svc_db_by_PK_auth_len;
  auth_data.name = (uint16_t *) DB_NAME;
  auth_data.vendor = (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;
  auth_data.attributes = SECVAR_ATTRIBUTES;
  auth_data.auth_db.pk = one_esl;
  auth_data.auth_db.pk_size = one_esl_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert,
                                      &cert_size, &data, &data_size);
  if (rc == SV_SUCCESS)
    rc = verify_signature (&auth_data, &timestamp, cert, cert_size, data, data_size,
                           &verified_flag);

  if (rc != SV_SUCCESS)
    printf ("Test Case-1 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-1 : PASSED\n");

  memset (&auth_data, 0x00, sizeof (auth_data_t));
  auth_data.auth_msg = svc_dbx_by_KEK_auth;
  auth_data.auth_msg_size = svc_dbx_by_KEK_auth_len;
  auth_data.name = (uint16_t *) DBX_NAME;
  auth_data.vendor = (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;
  auth_data.attributes = SECVAR_ATTRIBUTES;
  auth_data.auth_db.pk = one_esl;
  auth_data.auth_db.pk_size = one_esl_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert,
                                      &cert_size, &data, &data_size);
  if (rc == SV_SUCCESS)
    rc = verify_signature (&auth_data, &timestamp, cert, cert_size, data, data_size,
                           &verified_flag);

  if (rc != SV_FAILED_TO_VERIFY_SIGNATURE)
    printf ("Test Case-2 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-2 : PASSED\n");

  auth_data.auth_db.kek = kek_esl;
  auth_data.auth_db.kek_size = kek_esl_len;

  rc = verify_signature (&auth_data, &timestamp, cert, cert_size, data, data_size,
                         &verified_flag);
  if (rc != SV_SUCCESS)
    printf ("Test Case-3 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-3 : PASSED\n");

  memset (&auth_data, 0x00, sizeof (auth_data_t));
  auth_data.auth_msg = delete_pk_sbvs_auth;
  auth_data.auth_msg_size = delete_pk_sbvs_auth_len;
  auth_data.name = (uint16_t *) PK_NAME;
  auth_data.vendor = (uuid_t *) &SV_GLOBAL_VARIABLE_GUID;
  auth_data.attributes = 0x27;
  auth_data.auth_db.pk = one_esl;
  auth_data.auth_db.pk_size = one_esl_len;
  auth_data.auth_db.kek = kek_esl;
  auth_data.auth_db.kek_size = kek_esl_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert,
                                      &cert_size, &data, &data_size);
  if (rc == SV_SUCCESS)
    rc = verify_signature (&auth_data, &timestamp, cert, cert_size, data, data_size,
                           &verified_flag);

  if (rc != SV_SUCCESS)
    printf ("Test Case-4 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-4 : PASSED\n");

  memset (&auth_data, 0x00, sizeof (auth_data_t));
  auth_data.auth_msg = delete_pk_sesl_auth;
  auth_data.auth_msg_size = delete_pk_sesl_auth_len;
  auth_data.name = (uint16_t *) PK_NAME;
  auth_data.vendor = (uuid_t *) &SV_GLOBAL_VARIABLE_GUID;
  auth_data.attributes = 0x27;
  auth_data.auth_db.pk = one_esl;
  auth_data.auth_db.pk_size = one_esl_len;
  auth_data.auth_db.kek = kek_esl;
  auth_data.auth_db.kek_size = kek_esl_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert,
                                      &cert_size, &data, &data_size);
  if (rc == SV_SUCCESS)
    rc = verify_signature (&auth_data, &timestamp, cert, cert_size, data, data_size,
                           &verified_flag);

  if (rc != SV_SUCCESS)
    printf ("Test Case-5 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-5 : PASSED\n");

  memset (&auth_data, 0x00, sizeof (auth_data_t));
  auth_data.name = (uint16_t *) DB_NAME;
  auth_data.vendor = (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;
  auth_data.attributes = SECVAR_ATTRIBUTES;
  auth_data.flag = SV_VARIABLE_UPDATE_NO_FLAGS;
  auth_data.auth_msg = svc_db_by_PK_auth;
  auth_data.auth_msg_size = svc_db_by_PK_auth_len;
  auth_data.auth_db.pk = one_esl;
  auth_data.auth_db.pk_size = one_esl_len;

  rc = pseries_apply_update (&auth_data, &new_data, &new_data_size, &new_timestamp,
                             &verified_flag);
  if (rc != SV_SUCCESS)
    printf ("Test Case-6 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-6 : PASSED\n");

  memset (&auth_data, 0x00, sizeof (auth_data_t));
  auth_data.name = (uint16_t *) DBX_NAME;
  auth_data.vendor = (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;
  auth_data.attributes = SECVAR_ATTRIBUTES;
  auth_data.flag = SV_VARIABLE_UPDATE_NO_FLAGS;
  auth_data.auth_msg = svc_db_by_PK_auth;
  auth_data.auth_msg_size = svc_db_by_PK_auth_len;
  auth_data.auth_db.pk = one_esl;
  auth_data.auth_db.pk_size = one_esl_len;

  rc = unpack_authenticated_variable (&auth_data, &timestamp, &cert,
                                      &cert_size, &data, &data_size);
  assert (new_data_size == data_size);
  assert (memcmp (new_data, data, data_size) == 0);
  assert (memcmp (&timestamp, &new_timestamp, sizeof (timestamp_t)) == 0);

  /* attempt to apply to the wrong variable - sig mismatch */
  rc = pseries_apply_update (&auth_data, &new_data, &new_data_size, &new_timestamp,
                             &verified_flag);
  if (rc != SV_FAILED_TO_VERIFY_SIGNATURE)
    printf ("Test Case-7 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-7 : PASSED\n");


  memset (&auth_data, 0x00, sizeof (auth_data_t));
  auth_data.name = (uint16_t *) DB_NAME;
  auth_data.vendor = (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;
  auth_data.attributes = SECVAR_ATTRIBUTES;
  auth_data.flag = SV_VARIABLE_UPDATE_NO_FLAGS;
  auth_data.auth_msg = svc_db_by_PK_auth;
  auth_data.auth_msg_size = svc_db_by_PK_auth_len - data_size - 1;
  auth_data.auth_db.pk = one_esl;
  auth_data.auth_db.pk_size = one_esl_len;

  /* truncated update */
  rc = pseries_apply_update (&auth_data, &new_data, &new_data_size, &new_timestamp,
                             &verified_flag);
  if (rc != SV_AUTH_SIZE_INVALID)
    printf ("Test Case-8 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-8 : PASSED\n");

  memset (&auth_data, 0x00, sizeof (auth_data_t));
  auth_data.name = (uint16_t *) DB_NAME;
  auth_data.vendor = (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;
  auth_data.attributes = SECVAR_ATTRIBUTES;
  auth_data.flag = SV_VARIABLE_UPDATE_NO_FLAGS;
  auth_data.auth_msg = svc_db_by_PK_auth;
  auth_data.auth_msg_size = svc_db_by_PK_auth_len;
  auth_data.current_time = &new_timestamp;
  auth_data.current_esl_data = new_data;
  auth_data.current_esl_data_size = new_data_size;
  auth_data.auth_db.pk = one_esl;
  auth_data.auth_db.pk_size = one_esl_len;

  /* not in future */
  rc = pseries_apply_update (&auth_data, &new_data2, &new_data2_size, &new_timestamp2,
                             &verified_flag);
  if (rc != SV_TIMESTAMP_IN_PAST)
    printf ("Test Case-9 : FAILED with rc = 0x%x\n", rc);
  else
    printf ("Test Case-9 : PASSED\n");

  /* but permitted if we skip authentication */
  libstb_free (new_data);

  return 0;
}

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include "secvar/util.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include "secvar/pseries.h"
#include "libstb-secvar.h"
#include "data/PK_sv.h"
#include "data/KEK_by_PK_auth.h"
#include "data/db_by_KEK_auth.h"
#include "data/svc_db_by_PK_auth.h"
#include "data/kek_esl.h"
#include "data/dbx_1_auth.h"
#include "data/dbx_2_auth.h"
#include "data/dbx_256_a_esl.h"
#include "data/dbx_512_b_esl.h"
#include "data/wipe_by_PK_auth.h"
#include "data/priv_auth.h"
#include "libstb-secvar-errors.h"

#define PK_LABEL (uint8_t *)"P\0K\0"
#define KEK_LABEL (uint8_t *)"K\0E\0K\0"
#define DB_LABEL (uint8_t *)"d\0b\0"
#define DBX_LABEL (uint8_t *)"d\0b\0x\0"

int
main (int argc, char **argv)
{
  uint8_t *KEK = NULL, *db = NULL, *dbx = NULL, *tmp = NULL;
  size_t KEK_size = 0, db_size = 0, dbx_size = 0, tmp_size = 0;
  sv_err_t rc;
  uint64_t log_data;

  printf ("\n11 test cases for variable update request via phyp\n\n");

  /* load a KEK */
  rc = update_var_from_auth (KEK_LABEL, 6, KEK_by_PK_auth, KEK_by_PK_auth_len,
                             NULL, 0, false, false, PK_sv, PK_sv_len, NULL, 0,
                             &KEK, &KEK_size, &log_data);
  printf ("1 log_data: 0x%lx\n", log_data);
  if (rc)
    printf ("rc = %x\n", rc);
  assert (rc == 0);

  assert (KEK_size == kek_esl_len + 8); /* sizeof(pks_signed_var) == 8 */
  assert (memcmp (KEK + 8, kek_esl, kek_esl_len) == 0);

  /* try a db by KEK */
  rc = update_var_from_auth (DB_LABEL, 4, db_by_KEK_auth, db_by_KEK_auth_len,
                             NULL, 0, false, false, PK_sv, PK_sv_len, KEK,
                             KEK_size, &db, &db_size, &log_data);
  printf ("2 log_data: 0x%lx\n", log_data);
  if (rc)
    printf ("rc = %x\n", rc);
  assert (rc == 0);

  /* this update should fail as being too old */
  rc = update_var_from_auth (DB_LABEL, 4, svc_db_by_PK_auth, svc_db_by_PK_auth_len,
                             db, db_size, false, false, PK_sv, PK_sv_len, KEK,
                             KEK_size, &tmp, &tmp_size, &log_data);
  printf ("3 log_data: 0x%lx\n", log_data);
  if (rc != SV_TIMESTAMP_IN_PAST)
    printf ("rc = %x\n", rc);

  assert (rc == SV_TIMESTAMP_IN_PAST);
  assert (tmp == NULL);
  assert (tmp_size == 0);
  libstb_free (db);

  /* try a dbx */
  rc = update_var_from_auth (DBX_LABEL, 6, dbx_1_auth, dbx_1_auth_len, NULL, 0,
                             false, false, PK_sv, PK_sv_len, KEK, KEK_size,
                             &dbx, &dbx_size, &log_data);
  printf ("4 log_data: 0x%lx\n", log_data);
  if (rc)
    printf ("rc = %x\n", rc);
  assert (rc == 0);
  assert (dbx_size == dbx_256_a_esl_len + 8);
  assert (memcmp (dbx + 8, dbx_256_a_esl, dbx_256_a_esl_len) == 0);

  /* append another dbx */
  rc = update_var_from_auth (DBX_LABEL, 6, dbx_2_auth, dbx_2_auth_len, dbx,
                             dbx_size, false, true, PK_sv, PK_sv_len, KEK,
                             KEK_size, &tmp, &tmp_size, &log_data);
  printf ("5 log_data: 0x%lx\n", log_data);
  if (rc)
    printf ("rc = %x\n", rc);
  assert (rc == 0);
  assert (tmp_size == dbx_size + dbx_512_b_esl_len);
  assert (memcmp (tmp + 8 + dbx_256_a_esl_len, dbx_512_b_esl, dbx_512_b_esl_len) == 0);
  libstb_free (dbx);
  dbx = tmp;
  dbx_size = tmp_size;
  tmp = NULL;
  tmp_size = 0;

  /*
   * try an impermissible KEK update with allow unsigned PK updates
   * should still fail
   */
  rc = update_var_from_auth (KEK_LABEL, 6, KEK_by_PK_auth, KEK_by_PK_auth_len,
                             KEK, KEK_size, true, false, PK_sv, PK_sv_len, KEK,
                             KEK_size, &tmp, &tmp_size, &log_data);
  printf ("6 log_data: 0x%lx\n", log_data);
  if (rc != SV_TIMESTAMP_IN_PAST)
    printf ("rc = %x\n", rc);
  assert (rc == SV_TIMESTAMP_IN_PAST);
  assert (tmp == NULL);

  /* try an otherwise bad PK update with auPu */
  rc = update_var_from_auth (PK_LABEL, 4, KEK_by_PK_auth, KEK_by_PK_auth_len,
                             PK_sv, PK_sv_len, true, false, PK_sv, PK_sv_len,
                             KEK, KEK_size, &tmp, &tmp_size, &log_data);
  printf ("7 log_data: 0x%lx\n", log_data);
  if (rc)
    printf ("rc = %x\n", rc);
  assert (rc == 0);
  assert (tmp_size == KEK_size);
  assert (memcmp (tmp, KEK, KEK_size) == 0);
  libstb_free (tmp);
  tmp = NULL;
  tmp_size = 0;

  /*
   * try the wipe
   * .. validly signed, but allow unsigned PK updates is not set.
   */
  rc = update_var_from_auth (PK_LABEL, 4, wipe_by_PK_auth + APPEND_HEADER_LEN, wipe_by_PK_auth_len - APPEND_HEADER_LEN,
                             PK_sv, PK_sv_len, false, false, PK_sv, PK_sv_len,
                             KEK, KEK_size, &tmp, &tmp_size, &log_data);
  printf ("8 log_data: 0x%lx\n", log_data);
  if (rc != SV_INVALID_PK_UPDATE)
    printf ("rc = %x\n", rc);
  assert (rc == SV_INVALID_PK_UPDATE);

  rc = update_var_from_auth (PK_LABEL, 4, wipe_by_PK_auth + APPEND_HEADER_LEN, wipe_by_PK_auth_len - APPEND_HEADER_LEN,
                             PK_sv, PK_sv_len, true, false, PK_sv, PK_sv_len,
                             KEK, KEK_size, &tmp, &tmp_size, &log_data);
  printf ("9 log_data: 0x%lx\n", log_data);
  if (rc != SV_DELETE_EVERYTHING)
    printf ("rc = %x\n", rc);
  assert (rc == SV_DELETE_EVERYTHING);

  /* user defined variable signed by PK */
  rc = update_var_from_auth ((const uint8_t *) "P\0o\0w\0e\0r\0P\0r\0i\0v\0a\0t"
                                               "\0e\0V\0a\0r\0",
                             30, priv_auth, priv_auth_len, NULL, 0, false, false, PK_sv,
                             PK_sv_len, KEK, KEK_size, &tmp, &tmp_size, &log_data);
  printf ("10 log_data: 0x%lx\n", log_data);
  if (rc)
    printf ("rc = %x\n", rc);
  assert (rc == 0);
  assert (memcmp (tmp + 8, "private variable data\n", tmp_size - 8) == 0);
  libstb_free (tmp);

  /* bad name - odd bytes */
  rc = update_var_from_auth ((const uint8_t *) "P\0o\0w\0e\0r\0P\0r\0i\0v\0a\0t"
                                               "\0e\0V\0a\0r",
                             29, priv_auth, priv_auth_len, NULL, 0, false, false, PK_sv,
                             PK_sv_len, KEK, KEK_size, &tmp, &tmp_size, &log_data);
  printf ("11 log_data: 0x%lx\n", log_data);
  if (rc != SV_LABEL_IS_NOT_WIDE_CHARACTERS)
    printf ("rc = %x\n", rc);
  assert (rc == SV_LABEL_IS_NOT_WIDE_CHARACTERS);

  libstb_free (KEK);
  libstb_free (dbx);

  return 0;
}

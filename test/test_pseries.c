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
#include "data/delete_db_by_kek_sesl_auth.h"
#include "libstb-secvar-errors.h"
#include <log.h>
#include "test_utils.h"

#define PK_LABEL (uint8_t *)"P\0K\0"
#define KEK_LABEL (uint8_t *)"K\0E\0K\0"
#define DB_LABEL (uint8_t *)"d\0b\0"
#define DBX_LABEL (uint8_t *)"d\0b\0x\0"

int
main (int argc, char **argv)
{
  update_req_t update_req = { 0 };
  uint8_t *KEK = NULL, *db = NULL, *dbx = NULL, *tmp = NULL;
  size_t KEK_size = 0, db_size = 0, dbx_size = 0, tmp_size = 0;
  sv_err_t rc;

  libstb_log_level = 0;

  printf ("testing pseries variable update request...");

  update_req.label = KEK_LABEL;
  update_req.label_size = 6;
  update_req.allow_unauthenticated = false;
  update_req.append_update = false;
  update_req.update_data = KEK_by_PK_auth;
  update_req.update_data_size = KEK_by_PK_auth_len;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;

  /* load a KEK */
  rc = pseries_update_variable (&update_req, &KEK, &KEK_size);
  assert_rc (SV_SUCCESS);
  assert (KEK_size == kek_esl_len + 8);
  assert (memcmp (KEK + 8, kek_esl, kek_esl_len) == 0);

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = DB_LABEL;
  update_req.label_size = 4;
  update_req.allow_unauthenticated = false;
  update_req.append_update = false;
  update_req.update_data = db_by_KEK_auth;
  update_req.update_data_size = db_by_KEK_auth_len;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;

  /* try a db by KEK */
  rc = pseries_update_variable (&update_req, &db, &db_size);
  assert_rc (SV_SUCCESS);

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = DB_LABEL;
  update_req.label_size = 4;
  update_req.allow_unauthenticated = false;
  update_req.append_update = false;
  update_req.update_data = svc_db_by_PK_auth;
  update_req.update_data_size = svc_db_by_PK_auth_len;
  update_req.current_data = db;
  update_req.current_data_size = db_size;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;

  /* this update should fail as being too old */
  rc = pseries_update_variable (&update_req, &tmp, &tmp_size);
  assert_rc (SV_TIMESTAMP_IN_PAST);
  assert (tmp == NULL);
  assert (tmp_size == 0);

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = DB_LABEL;
  update_req.label_size = 4;
  update_req.allow_unauthenticated = false;
  update_req.append_update = false;
  update_req.update_data = delete_db_by_kek_sesl_auth;
  update_req.update_data_size = delete_db_by_kek_sesl_auth_len;
  update_req.current_data = db;
  update_req.current_data_size = db_size;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;

  /* deleting keys on db using KEK*/
  rc = pseries_update_variable (&update_req, &tmp, &tmp_size);
  assert_rc (SV_SUCCESS);
  assert (tmp != NULL);
  assert (tmp_size == 8);

  libstb_free (tmp);
  libstb_free (db);

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = DBX_LABEL;
  update_req.label_size = 6;
  update_req.allow_unauthenticated = false;
  update_req.append_update = false;
  update_req.update_data = dbx_1_auth;
  update_req.update_data_size = dbx_1_auth_len;
  update_req.current_data = NULL;
  update_req.current_data_size = 0;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;

  /* try a dbx */
  rc = pseries_update_variable (&update_req, &dbx, &dbx_size);
  assert_rc (SV_SUCCESS);
  assert (dbx_size == dbx_256_a_esl_len + 8);
  assert (memcmp (dbx + 8, dbx_256_a_esl, dbx_256_a_esl_len) == 0);

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = DBX_LABEL;
  update_req.label_size = 6;
  update_req.allow_unauthenticated = false;
  update_req.append_update = true;
  update_req.update_data = dbx_2_auth;
  update_req.update_data_size = dbx_2_auth_len;
  update_req.current_data = dbx;
  update_req.current_data_size = dbx_size;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;

  /* append another dbx */
  rc = pseries_update_variable (&update_req, &tmp, &tmp_size);
  assert_rc (SV_SUCCESS);
  assert (tmp_size == dbx_size + dbx_512_b_esl_len);
  assert (memcmp (tmp + 8 + dbx_256_a_esl_len, dbx_512_b_esl, dbx_512_b_esl_len) == 0);

  libstb_free (dbx);
  dbx = tmp;
  dbx_size = tmp_size;
  tmp = NULL;
  tmp_size = 0;

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = KEK_LABEL;
  update_req.label_size = 6;
  update_req.allow_unauthenticated = true;
  update_req.append_update = false;
  update_req.update_data = KEK_by_PK_auth;
  update_req.update_data_size = KEK_by_PK_auth_len;
  update_req.current_data = KEK;
  update_req.current_data_size = KEK_size;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;
  /*
   * try an impermissible KEK update with allow unsigned PK updates
   * should still fail
   */
  rc = pseries_update_variable (&update_req, &tmp, &tmp_size);
  assert_rc (SV_TIMESTAMP_IN_PAST);
  assert (tmp == NULL);

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = PK_LABEL;
  update_req.label_size = 4;
  update_req.allow_unauthenticated = true;
  update_req.append_update = false;
  update_req.update_data = KEK_by_PK_auth;
  update_req.update_data_size = KEK_by_PK_auth_len;
  update_req.current_data = PK_sv;
  update_req.current_data_size = PK_sv_len;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;

  /* try an otherwise bad PK update with auPu */
  rc = pseries_update_variable (&update_req, &tmp, &tmp_size);
  assert_rc (SV_SUCCESS);
  assert (tmp_size == KEK_size);
  assert (memcmp (tmp, KEK, KEK_size) == 0);

  libstb_free (tmp);
  tmp = NULL;
  tmp_size = 0;

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = PK_LABEL;
  update_req.label_size = 4;
  update_req.allow_unauthenticated = false;
  update_req.append_update = false;
  update_req.update_data = wipe_by_PK_auth + APPEND_HEADER_LEN;
  update_req.update_data_size = wipe_by_PK_auth_len - APPEND_HEADER_LEN;
  update_req.current_data = PK_sv;
  update_req.current_data_size = PK_sv_len;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;
  /*
   * try the wipe
   *.. validly signed, but allow unsigned PK updates is not set.
   */
  rc = pseries_update_variable (&update_req, &tmp, &tmp_size);
  assert_rc (SV_INVALID_PK_UPDATE);

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = PK_LABEL;
  update_req.label_size = 4;
  update_req.allow_unauthenticated = true;
  update_req.append_update = false;
  update_req.update_data = wipe_by_PK_auth + APPEND_HEADER_LEN;
  update_req.update_data_size = wipe_by_PK_auth_len - APPEND_HEADER_LEN;
  update_req.current_data = PK_sv;
  update_req.current_data_size = PK_sv_len;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;

  rc = pseries_update_variable (&update_req, &tmp, &tmp_size);
  assert_rc (SV_DELETE_EVERYTHING);

  memset (&update_req, 0x00, sizeof (update_req_t));
  update_req.label = (uint8_t *) "P\0o\0w\0e\0r\0P\0r\0i\0v"
                                 "\0a\0t\0e\0V\0a\0r\0";
  update_req.label_size = 30;
  update_req.allow_unauthenticated = false;
  update_req.append_update = false;
  update_req.update_data = priv_auth;
  update_req.update_data_size = priv_auth_len;
  update_req.current_data = NULL;
  update_req.current_data_size = 0;
  update_req.auth_db.pk = PK_sv;
  update_req.auth_db.pk_size = PK_sv_len;
  update_req.auth_db.kek = KEK;
  update_req.auth_db.kek_size = KEK_size;

  /* user defined variable signed by PK */
  rc = pseries_update_variable (&update_req, &tmp, &tmp_size);
  assert_rc (SV_SUCCESS);
  assert (memcmp (tmp + 8, "private variable data\n", tmp_size - 8) == 0);
  libstb_free (tmp);

  libstb_free (KEK);
  libstb_free (dbx);

  printf ("PASS\n");

  return 0;
}

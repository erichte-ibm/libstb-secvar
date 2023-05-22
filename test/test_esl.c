/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include "external/edk2/common.h"
#include "secvar/esl.h"
#include "data/one_esl.h"
#include "data/kek_esl.h"
#include "data/two_esl.h"
#include "data/dbx_256_a_esl.h"
#include "data/dbx_256_b_esl.h"
#include "data/dbx_512_a_esl.h"
#include "data/dbx_512_b_esl.h"
#include "libstb-secvar-errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <log.h>
#include "test_utils.h"

int
main (int argc, char **argv)
{
  const uint8_t *tmp;
  sv_err_t rc;
  const uint8_t *cert = NULL, *cert1;
  uint8_t *merge;
  size_t cert_size, merge_size;
  uuid_t owner;

  libstb_log_level = 0;

  printf ("testing esl merge...");

  rc = next_cert_from_esls_buf (one_esl, one_esl_len, &cert, &cert_size, &owner, &tmp);

  assert_rc (SV_SUCCESS);
  assert (cert != NULL);
  assert (cert_size == 813);

  rc = next_cert_from_esls_buf (one_esl, one_esl_len, &cert, &cert_size, &owner, &tmp);

  assert_rc (SV_SUCCESS);
  assert (cert == NULL);
  
  rc = next_cert_from_esls_buf (two_esl, two_esl_len, &cert, &cert_size, &owner, &tmp);
  
  assert_rc (SV_SUCCESS);
  assert (cert != NULL);
  assert (cert_size == 813);

  cert1 = cert;
  rc = next_cert_from_esls_buf (two_esl, two_esl_len, &cert, &cert_size, &owner, &tmp);

  assert_rc (SV_SUCCESS);
  assert (cert != NULL);
  assert (cert_size == 813);
  assert (cert > cert1);

  rc = next_cert_from_esls_buf (two_esl, two_esl_len, &cert, &cert_size, &owner, &tmp);

  assert_rc (SV_SUCCESS);
  assert (cert == NULL);
  
  rc = merge_esls (one_esl, one_esl_len, kek_esl, kek_esl_len, NULL, &merge_size);

  assert_rc (SV_SUCCESS);
  assert (cert == NULL);
  assert (merge_size > one_esl_len);
  assert (merge_size > kek_esl_len);
  
#ifdef DO_NOT_MERGE_CERTIFICATE_ESLS
  assert (merge_size == one_esl_len + kek_esl_len);
#else
  assert (merge_size == one_esl_len + kek_esl_len - sizeof (sv_esl_t));
#endif
  merge = malloc (merge_size);
  assert (merge);
  rc = merge_esls (one_esl, one_esl_len, kek_esl, kek_esl_len, merge, &merge_size);
  assert_rc (SV_SUCCESS);
  assert (merge_size > one_esl_len && merge_size > kek_esl_len);
#ifdef DO_NOT_MERGE_CERTIFICATE_ESLS
  assert (merge_size == one_esl_len + kek_esl_len);
  assert (memcmp (one_esl, merge, one_esl_len) == 0);
  assert (memcmp (kek_esl, merge + one_esl_len, kek_esl_len) == 0);
#else
  assert (merge_size == one_esl_len + kek_esl_len - sizeof (sv_esl_t));
  assert (memcmp (one_esl + sizeof (sv_esl_t), merge + sizeof (sv_esl_t),
                  one_esl_len - sizeof (sv_esl_t)) == 0);
#endif
  free (merge);

  rc = merge_esls (dbx_256_a_esl, dbx_256_a_esl_len, dbx_256_b_esl,
                   dbx_256_b_esl_len, NULL, &merge_size);

  assert_rc (SV_SUCCESS);
  assert(merge_size == dbx_256_a_esl_len + dbx_256_b_esl_len - sizeof (sv_esl_t));

  rc = merge_esls (dbx_256_a_esl, dbx_256_a_esl_len, dbx_512_b_esl,
                   dbx_512_b_esl_len, NULL, &merge_size);

  assert_rc (SV_SUCCESS);
  assert(merge_size == dbx_256_a_esl_len + dbx_512_b_esl_len);

  printf("PASS\n");

  return 0;
}

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

int
main (int argc, char **argv)
{
  const uint8_t *tmp;
  sv_err_t rc;
  const uint8_t *cert = NULL, *cert1;
  uint8_t *merge;
  size_t cert_size, merge_size;
  uuid_t owner;

  printf ("\n8 test cases for ESL merge\n\n");

  rc = next_cert_from_esls_buf (one_esl, one_esl_len, &cert, &cert_size, &owner, &tmp);
  if (rc == SV_SUCCESS && cert != NULL && cert_size == 813)
    printf ("Test case-1 : PASSED\n");
  else
    {
      printf ("Test case-1 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  rc = next_cert_from_esls_buf (one_esl, one_esl_len, &cert, &cert_size, &owner, &tmp);
  if (rc == SV_SUCCESS && cert == NULL)
    printf ("Test case-2 : PASSED\n");
  else
    {
      printf ("Test case-2 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  rc = next_cert_from_esls_buf (two_esl, two_esl_len, &cert, &cert_size, &owner, &tmp);
  if (rc == SV_SUCCESS && cert != NULL && cert_size == 813)
    printf ("Test case-3 : PASSED\n");
  else
    {
      printf ("Test case-3 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  cert1 = cert;
  rc = next_cert_from_esls_buf (two_esl, two_esl_len, &cert, &cert_size, &owner, &tmp);
  if (rc == SV_SUCCESS && cert != NULL && cert_size == 813 && cert > cert1)
    printf ("Test case-4 : PASSED\n");
  else
    {
      printf ("Test case-4 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  rc = next_cert_from_esls_buf (two_esl, two_esl_len, &cert, &cert_size, &owner, &tmp);
  if (rc == SV_SUCCESS && cert == NULL)
    printf ("Test case-5 : PASSED\n");
  else
    {
      printf ("Test case-5 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  rc = merge_esls (one_esl, one_esl_len, kek_esl, kek_esl_len, NULL, &merge_size);
  if (rc == SV_SUCCESS && cert == NULL && merge_size > one_esl_len && merge_size > kek_esl_len)
    printf ("Test case-6 : PASSED\n");
  else
    {
      printf ("Test case-6 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

#ifdef DO_NOT_MERGE_CERTIFICATE_ESLS
  assert (merge_size == one_esl_len + kek_esl_len);
#else
  assert (merge_size == one_esl_len + kek_esl_len - sizeof (sv_esl_t));
#endif
  merge = malloc (merge_size);
  assert (merge);
  rc = merge_esls (one_esl, one_esl_len, kek_esl, kek_esl_len, merge, &merge_size);
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
  if (rc == SV_SUCCESS && merge_size == dbx_256_a_esl_len + dbx_256_b_esl_len - sizeof (sv_esl_t))
    printf ("Test case-7 : PASSED\n");
  else
    {
      printf ("Test case-7 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  rc = merge_esls (dbx_256_a_esl, dbx_256_a_esl_len, dbx_512_b_esl,
                   dbx_512_b_esl_len, NULL, &merge_size);
  if (rc == SV_SUCCESS && merge_size == dbx_256_a_esl_len + dbx_512_b_esl_len)
    printf ("Test case-8 : PASSED\n");
  else
    {
      printf ("Test case-8 : FAILED with rc = 0x%x\n", rc);
      return 0;
    }

  return 0;
}

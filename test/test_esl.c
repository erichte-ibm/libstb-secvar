/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include "external/edk2/common.h"
#include "secvar/esl.h"
#include "data/one_esl.h"
#include "data/kek_esl.h"
#include "data/two_esl.h"
#include "data/too_small.h"
#include "data/too_big.h"
#include "data/sig_too_large.h"
#include "data/sighdr_too_large.h"
#include "data/zero_sig.h"
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
  uint8_t tmp_two_esl[sizeof(two_esl)+1] = {0};
  const uint8_t *tmp_esl;
  size_t esl_size;

  libstb_log_level = 0;

  printf ("testing esl functions...");

  // Copy two_esl into a slightly larger buffer for trailing data check without overruning the actual
  memcpy(tmp_two_esl, two_esl, two_esl_len);
  
  /* next_esl_from_buffer checks */
  rc = next_esl_from_buffer (NULL, 0, NULL, NULL);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);  
  rc = next_esl_from_buffer (two_esl, two_esl_len, NULL, NULL);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);
  rc = next_esl_from_buffer (two_esl, 0, (const uint8_t **) &tmp_two_esl, &esl_size);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);

  // Check pointer before the buffer
  tmp_esl = (uint8_t *) (((long) two_esl) - 1); // Blatantly get an out-of-bounds pointer, circumvent cppcheck
  rc = next_esl_from_buffer (tmp_two_esl, two_esl_len, &tmp_esl, &esl_size);
  assert_msg (rc == SV_BUF_INSUFFICIENT_DATA, "expected insufficent data, got rc = %d\n", rc);
  tmp_esl = two_esl + two_esl_len + 1;
  // Check pointer after the buffer
  rc = next_esl_from_buffer (tmp_two_esl, two_esl_len, &tmp_esl, &esl_size);
  assert_msg (rc == SV_BUF_INSUFFICIENT_DATA, "expected insufficent data, got rc = %d\n", rc);

  // Check that there is enough (remaining) space for an ESL in the buffer
  tmp_esl = NULL;
  rc = next_esl_from_buffer(tmp_two_esl, sizeof(sv_esl_t) - 1, &tmp_esl, &esl_size);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);

  // First success iteration
  tmp_esl = NULL;
  rc = next_esl_from_buffer (tmp_two_esl, two_esl_len, &tmp_esl, &esl_size);
  assert (rc == SV_SUCCESS);
  assert (esl_size == 857);
  assert (tmp_esl == tmp_two_esl);

  // Second success iteration
  rc = next_esl_from_buffer (tmp_two_esl, two_esl_len, &tmp_esl, &esl_size);
  assert (rc == SV_SUCCESS);
  assert (esl_size == 857);
  assert (tmp_esl == tmp_two_esl + 857);

  cert = tmp_esl; // Borrow this variable temporarily to store the correct position of the last esl

  // Check the trailing data error,
  //  it should be caught here since there are two esls, and we are widening the bounds slightly
  rc = next_esl_from_buffer (tmp_two_esl, two_esl_len + 1, &tmp_esl, &esl_size);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);

  tmp_esl = cert;
  cert = NULL;

  rc = next_esl_from_buffer (tmp_two_esl, two_esl_len, &tmp_esl, &esl_size);
  assert (rc == SV_SUCCESS);
  assert (tmp_esl == NULL);
  // If the return ESL is NULL, we do not return a meaningful value in size. Perhaps we should.
  // assert (esl_size == 0);

  // Test invalid ESLs, consider just testing esl_internal_sizes_sensible directly
  tmp_esl = NULL;
  rc = next_esl_from_buffer (too_small_esl, too_small_esl_len, &tmp_esl, &esl_size);
  assert (rc == SV_ESL_SIZE_INVALID);
  assert (tmp_esl == NULL);
  rc = next_esl_from_buffer (too_big_esl, too_big_esl_len, &tmp_esl, &esl_size);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);
  rc = next_esl_from_buffer (sighdr_too_large_esl, sighdr_too_large_esl_len, &tmp_esl, &esl_size);
  assert (rc == SV_ESL_SIZE_INVALID);
  rc = next_esl_from_buffer (sig_too_large_esl, sig_too_large_esl_len, &tmp_esl, &esl_size);
  assert (rc == SV_ESL_SIZE_INVALID);
  rc = next_esl_from_buffer (zero_sig_esl, zero_sig_esl_len, &tmp_esl, &esl_size);
  assert (rc == SV_ESL_SIZE_INVALID);
  
  /* next_esd_from_esl checks */
  const uint8_t *esd_data;
  size_t esd_size;
  uuid_t esd_owner;
  // Check NULL args
  rc = next_esd_from_esl(NULL, &esd_data, &esd_size, &esd_owner);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);
  rc = next_esd_from_esl(one_esl, NULL, &esd_size, &esd_owner);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);
  rc = next_esd_from_esl(one_esl, &esd_data, NULL, &esd_owner);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);

  // Check current ESD address is within the bounds of the ESL
  esd_data = (uint8_t *) (((long) one_esl) - 1);
  rc = next_esd_from_esl(one_esl, &esd_data, &esd_size, &esd_owner);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);
  esd_data = one_esl + one_esl_len + 1;
  rc = next_esd_from_esl(one_esl, &esd_data, &esd_size, &esd_owner);
  assert (rc == SV_BUF_INSUFFICIENT_DATA);

  // Unlikely to occur, but test passing in an ESL with invalid signature size
  esd_data = NULL;
  rc = next_esd_from_esl(sig_too_large_esl, &esd_data, &esd_size, &esd_owner);
  assert (rc == SV_ESL_SIZE_INVALID);
  
  /* next_cert_from_esls_buf checks */
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
  
  /* merge esls checks */
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

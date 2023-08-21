/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "log.h"
#include "config.h"
#include "secvar/esl.h"
#include "secvar/crypto.h"
#include "secvar/util.h"
#include "secvar/pseries.h"
#include "secvar/authentication_2.h"

/*
 * Can this update be verified by the KEK?
 * Updates that _cannot_ be verified by KEK: PK & KEK under
 * SV_GLOBAL_VARIABLE_GUID. Anything else is fair game.
 * Assumes that _elsewhere_ you verify that no-one is sticking other variables
 * in the SV_GLOBAL_VARIABLE_GUID space!
 */
static bool
kek_can_verify (const auth_data_t *auth_data)
{
  if (!uuid_equals (auth_data->vendor, &SV_GLOBAL_VARIABLE_GUID))
    return true;

  return false;
}

/* verify against PK keys */
static sv_err_t
verify_aginst_pk (const auth_db_t *auth_db, crypto_pkcs7_t *pkcs7,
                  uint8_t *hash, sv_flag_t *verified_flag)
{
  sv_err_t rc = SV_FAILED_TO_VERIFY_SIGNATURE;
  const uint8_t *tmp = NULL;
  uuid_t cert_owner = { 0 };
  const uint8_t *cert = NULL;
  size_t cert_size = 0;
  crypto_x509_t *pk = NULL;

  if (auth_db->pk != NULL && auth_db->pk_size != 0)
    {
      rc = next_cert_from_esls_buf (auth_db->pk, auth_db->pk_size, &cert, &cert_size,
                                    &cert_owner, &tmp);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "Error parsing PK ESL for cert.\n");
          return rc;
        }

      rc = crypto.get_x509_certificate (cert, cert_size, &pk);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "Error parsing PK cert to X.509 structure");
          return SV_X509_PARSE_ERROR;
        }

      /*
       * TODO maybe this is too harsh? - we could try a KEK?
       * you can recover by doing an unauthenticated PK update
       */
      rc = crypto.validate_x509_certificate (pk);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "PK cert is not a good RSA cert.\n");
          crypto_x509_free (pk);
          return rc;
        }

      /*
       * we are safe to pass 32 here because we verified that it was
       * sha256 above.
       */
      rc = crypto.verify_pkcs7_signature (pkcs7, pk, hash, MAX_HASH_SIZE);
      crypto_x509_free (pk);
      if (rc != SV_SUCCESS)
        return SV_FAILED_TO_VERIFY_SIGNATURE;
      else
        *verified_flag = SV_AUTH_VERIFIED_BY_PK;
    }

  return rc;
}

/* verify against KEK keys */
static sv_err_t
verify_aginst_kek (const auth_db_t *auth_db, crypto_pkcs7_t *pkcs7,
                   uint8_t *hash, sv_flag_t *verified_flag)
{
  sv_err_t rc = SV_FAILED_TO_VERIFY_SIGNATURE;
  const uint8_t *tmp = NULL;
  uuid_t cert_owner = { 0 };
  const uint8_t *cert = NULL;
  size_t cert_size = 0;
  crypto_x509_t *kek = NULL;

  if (auth_db->kek != NULL && auth_db->kek_size)
    {
      rc = next_cert_from_esls_buf (auth_db->kek, auth_db->kek_size, &cert, &cert_size,
                                    &cert_owner, &tmp);
      while (rc == SV_SUCCESS && cert != NULL)
        {
          /*
           * We take a pretty hard-line approach here:
           * if a KEK fails to parse or be RSA-2048, we bail,
           * even if a later KEK might work.
           */
          rc = crypto.get_x509_certificate (cert, cert_size, &kek);
          if (rc != SV_SUCCESS)
            {
              prlog (PR_ERR, "Error parsing KEK cert to X.509 structure");
              return SV_X509_PARSE_ERROR;
            }

          rc = crypto.validate_x509_certificate (kek);
          if (rc != SV_SUCCESS)
            {
              prlog (PR_ERR, "KEK cert is not a good RSA cert.\n");
              crypto_x509_free (kek);
              return rc;
            }

          rc = crypto.verify_pkcs7_signature (pkcs7, kek, hash, MAX_HASH_SIZE);
          crypto_x509_free (kek);
          if (rc == SV_SUCCESS)
            {
              *verified_flag = SV_AUTH_VERIFIED_BY_KEK;
              return rc;
            }

          rc = next_cert_from_esls_buf (auth_db->kek, auth_db->kek_size, &cert,
                                        &cert_size, &cert_owner, &tmp);
        }

      if (rc != SV_SUCCESS)
        prlog (PR_ERR, "Error parsing KEK ESLs for cert, or trailing data\n");
    }

  return rc;
}

/*
 * Given a variable update from a EDK2 EFI_VARIABLE_AUTHENTICATION_2 format
 * message, determine if it is validly signed.
 */
sv_err_t
verify_signature (const auth_data_t *auth_data, const timestamp_t *timestamp,
                  const uint8_t *cert_data, const size_t cert_data_size,
                  const uint8_t *esl_data, const size_t esl_data_size,
                  sv_flag_t *verified_flag)
{
  sv_err_t rc = SV_SUCCESS;
  uint8_t hash[MAX_HASH_SIZE] = { 0 };
  crypto_pkcs7_t *pkcs7 = NULL;

  /* convert cert into PKCS#7 structure */
  rc = crypto.get_pkcs7_certificate (cert_data, cert_data_size, &pkcs7);
  if (rc != SV_SUCCESS)
    {
      prlog (PR_ERR, "PKCS#7 message failed to parse as DER.\n");
      return rc;
    }

  /* Only SHA-256 is permitted */
  rc = crypto.pkcs7_md_is_sha256 (pkcs7);
  if (rc != SV_SUCCESS)
    {
      prlog (PR_ERR, "PKCS#7 message wasn't SHA-256.\n");
      rc = SV_UNEXPECTED_PKCS7_ALGO;
    }
  else
    {
      /* generate hash */
      rc = construct_auth2_hash (auth_data, timestamp, esl_data, esl_data_size, hash);
      if (rc != SV_SUCCESS)
        prlog (PR_ERR, "Error constructing auth2 hash.\n");
      else
        {
          rc = verify_aginst_pk (&auth_data->auth_db, pkcs7, hash, verified_flag);
          if (rc == SV_FAILED_TO_VERIFY_SIGNATURE && kek_can_verify (auth_data))
            rc = verify_aginst_kek (&auth_data->auth_db, pkcs7, hash, verified_flag);

          if (rc != SV_SUCCESS)
            {
              rc = SV_FAILED_TO_VERIFY_SIGNATURE;
              prlog (PR_ERR, "Could not verify PKCS#7 signature against trusted key\n");
            }
        }
    }

  crypto_pkcs7_free (pkcs7);

  return rc;
}

/*
 * Is timestamp A after timestamp B?
 * @a: timestamp 1
 * @b: timestamp 2
 * returns: a > b
 * assumes that the usual fields are nulled out!
 */
static bool
is_after (const timestamp_t *a, const timestamp_t *b)
{
  if (le16_to_cpu (a->year) != le16_to_cpu (b->year))
    return le16_to_cpu (a->year) > le16_to_cpu (b->year);
  if (a->month != b->month)
    return a->month > b->month;
  if (a->day != b->day)
    return a->day > b->day;
  if (a->hour != b->hour)
    return a->hour > b->hour;
  if (a->minute != b->minute)
    return a->minute > b->minute;
  if (a->second != b->second)
    return a->second > b->second;

  return false;
}

/* append new esl */
static sv_err_t
append_update (const auth_data_t *auth_data, const uint8_t *esl_data,
               const size_t esl_data_size, uint8_t **new_esl_data, size_t *new_esl_data_size)
{
  sv_err_t rc = SV_SUCCESS;

  if (uuid_equals (auth_data->vendor, &SV_IMAGE_SECURITY_DATABASE_GUID))
    {
      rc = merge_esls (auth_data->current_esl_data, auth_data->current_esl_data_size, esl_data,
                       esl_data_size, NULL, new_esl_data_size);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "Error calculating size for merging ESLs\n");
          return rc;
        }

      *new_esl_data = (uint8_t *) libstb_zalloc (*new_esl_data_size);
      if (*new_esl_data == NULL)
        {
          prlog (PR_ERR, "Allocation for new esl data failed\n");
          return SV_ALLOCATION_FAILED;
        }
      rc = merge_esls (auth_data->current_esl_data, auth_data->current_esl_data_size, esl_data,
                       esl_data_size, *new_esl_data, new_esl_data_size);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "Error merging ESLs!\n");
          libstb_free (*new_esl_data);
          return rc;
        }
    }
  else
    {
      *new_esl_data_size = auth_data->current_esl_data_size + esl_data_size;
      *new_esl_data = (uint8_t *) libstb_zalloc (*new_esl_data_size);
      if (*new_esl_data == NULL)
        {
          prlog (PR_ERR, "Allocation for new esl data failed\n");
          return SV_ALLOCATION_FAILED;
        }

      memcpy (*new_esl_data, auth_data->current_esl_data, auth_data->current_esl_data_size);
      memcpy (*new_esl_data + auth_data->current_esl_data_size, esl_data, esl_data_size);
    }

  return rc;
}

/*
 * Given a variable update, determine if it is validly signed, and apply it.
 * Validates signature and timestamp. If the variable is a EFI_IMAGE_SECURITY_DATABASE
 * (i.e. db, dbx) and the append attribute is set, performs an ESL merge with current data.
 *
 * Beyond that, no verification is done:
 *  - no verification of initial writes to db/dbx
 *  - no verification for db/dbx that ESL GUIDs make sense for the variable
 *  - no verification at all on the contents of any other variable.
 *
 * If new_esl_data_size is 0, new_esl_data will be NULL. This represents variable deletion.
 * return code: SUCCESS if the update was valid, otherwise an error code.
 *
 * Lifetime: new_esl_data is a fresh allocation if rc = SUCCESS. Caller must free with libstb_free().
 */
sv_err_t
pseries_apply_update (const auth_data_t *auth_data, uint8_t **new_esl_data,
                      size_t *new_esl_data_size, timestamp_t *new_time,
                      sv_flag_t *verified_flag)
{
  sv_err_t rc = SV_SUCCESS;
  timestamp_t update_time = { 0 };
  const uint8_t *cert_data = NULL, *esl_data = NULL;
  size_t cert_data_size = 0, esl_data_size = 0;
  bool is_append = auth_data->attributes & SV_VARIABLE_APPEND_WRITE;

  /* the auth data must parse as valid auth data */
  rc = unpack_authenticated_variable (auth_data, &update_time, &cert_data,
                                      &cert_data_size, &esl_data, &esl_data_size);
  if (rc != SV_SUCCESS)
    {
      prlog (PR_ERR, "Error unpacking update's auth2 structure.\n");
      return rc;
    }

  /* the signature must pass validation */
  if (!(auth_data->flag & SV_VARIABLE_UPDATE_SKIP_VERIFICATION))
    {
      rc = verify_signature (auth_data, &update_time, cert_data, cert_data_size,
                             esl_data, esl_data_size, verified_flag);
      if (rc != SV_SUCCESS)
        return rc;
    }
  else
    *verified_flag = SV_AUTH_VERIFIED_BY_PK;

  /*
   * unless:
   * - there is no current variable or
   *  - we are skipping verification or
   *  - this is an append update
   * then the time must be ahead
   */
  if (!((auth_data->current_time == NULL) ||
      (auth_data->flag & SV_VARIABLE_UPDATE_SKIP_VERIFICATION) || is_append))
    {
      if (!is_after (&update_time, auth_data->current_time))
        return SV_TIMESTAMP_IN_PAST;
    }

  if (is_append && auth_data->current_esl_data != NULL &&
      auth_data->current_esl_data_size != 0)
    {
      rc = append_update (auth_data, esl_data, esl_data_size, new_esl_data, new_esl_data_size);
      if (rc == SV_SUCCESS)
        {
          if (auth_data->current_time == NULL || is_after (&update_time, auth_data->current_time))
            *new_time = update_time;
          else
            *new_time = *auth_data->current_time;
        }
    }
  else
    {
      *new_esl_data_size = esl_data_size;
      if (esl_data_size != 0)
        {
          *new_esl_data = (uint8_t *) libstb_zalloc (*new_esl_data_size);
          if (*new_esl_data == NULL)
            {
              prlog (PR_ERR, "Allocation for new data failed\n");
              return SV_ALLOCATION_FAILED;
            }

          memcpy (*new_esl_data, esl_data, esl_data_size);
        }
      else
        {
          *new_esl_data = NULL;
        }

      *new_time = update_time;
    }

  return SV_SUCCESS;
}

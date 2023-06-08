/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include <stdint.h>
#include <stdbool.h>
#include "log.h"
#include "config.h"
#include "secvar/crypto.h"
#include "secvar/util.h"
#include "secvar/esl.h"
#include "secvar/pseries.h"

#define ESL_HEADER_SIZE 44

struct var_timestamp
{
  leint16_t year;
  uint8_t month;
  uint8_t day;
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
} SV_PACKED;

typedef struct var_timestamp var_timestamp_t;

struct signed_variable
{
  uint8_t version; /* must be 0 */
  var_timestamp_t time;
} SV_PACKED;

/*
 * PK and KEK
 */
const uint8_t global_variable[2][20] = {"P\0K\0\0\0", "K\0E\0K\0\0\0"};

/*
 * 1. db
 * 2. dbx
 * 3. grubdb
 * 4. grubdbx
 * 5. sbat
 * 6. moduledb
 * 7. trustedcadb
 */
const uint8_t security_variable[7][30] = {"d\0b\0\0\0", "d\0b\0x\0\0\0",
                                          "g\0r\0u\0b\0d\0b\0\0\0",
                                          "g\0r\0u\0b\0d\0b\0x\0\0\0",
                                          "s\0b\0a\0t\0\0\0",
                                          "m\0o\0d\0u\0l\0e\0d\0b\0\0\0",
                                          "t\0r\0u\0s\0t\0e\0d\0c\0a\0d\0b\0\0\0"};

/* lifetime: out-data is a pointer into in-data */
static sv_err_t
unpack_signed_var (const uint8_t *in, size_t in_size, const uint8_t **out_data,
                   size_t *out_size, timestamp_t *timestamp)
{
  const struct signed_variable *signed_var;
  timestamp_t ts = { 0 };

  /* do not permit negative */
  if (in_size < sizeof (struct signed_variable))
    return SV_UNPACK_ERROR;

  signed_var = (const struct signed_variable *) in;
  if (signed_var->version != 0)
    return SV_UNPACK_VERSION_ERROR;

  ts.year = signed_var->time.year;
  ts.month = signed_var->time.month;
  ts.day = signed_var->time.day;
  ts.hour = signed_var->time.hour;
  ts.minute = signed_var->time.minute;
  ts.second = signed_var->time.second;
  *timestamp = ts;

  *out_data = in + sizeof (struct signed_variable);
  *out_size = in_size - sizeof (struct signed_variable);

  return SV_SUCCESS;
}

static sv_err_t
pack_signed_var (const uint8_t *data, const size_t size, const timestamp_t *time,
                 uint8_t **packed_data, size_t *packed_size)
{
  struct signed_variable *signed_var;

  /* a PKS object has its size stored in a 16-bit so make sure we don't overflow that */
  if (size > 0xffffUL - sizeof (struct signed_variable))
    return SV_TOO_MUCH_DATA;

  *packed_size = size + sizeof (struct signed_variable);
  *packed_data = (uint8_t *) libstb_zalloc (*packed_size);
  if (!*packed_data)
    return SV_ALLOCATION_FAILED;

  signed_var = (struct signed_variable *) *packed_data;

  signed_var->version = 0;
  signed_var->time.year = time->year;
  signed_var->time.month = time->month;
  signed_var->time.day = time->day;
  signed_var->time.hour = time->hour;
  signed_var->time.minute = time->minute;
  signed_var->time.second = time->second;

  if (data != NULL && size != 0)
    memcpy (*packed_data + sizeof (struct signed_variable), data, size);

  return SV_SUCCESS;
}

static bool
cert_parses_as_good_RSA (const uint8_t *cert_data, size_t cert_size, const bool check_CA)
{
  int rc;
  crypto_x509_t *cert;

  rc = crypto.get_x509_certificate (cert_data, cert_size, &cert);
  if (rc != SV_SUCCESS)
    return false;

  /* must be RSA-2048/4096 */
  rc = crypto.validate_x509_certificate (cert);
  if (rc != SV_SUCCESS)
    {
      prlog (PR_ERR, "certificate validation failed (%d)\n", rc);
      crypto.release_x509_certificate (cert);
      return false;
    }

  if (check_CA && !crypto.validate_x509_certificate_CA (cert))
    {
      prlog (PR_ERR, "it is not CA certificate\n");
      crypto.release_x509_certificate (cert);
      return false;
    }

  crypto.release_x509_certificate (cert);

  return true;
}

/* convert label to a wide character name */
static sv_err_t
convert_to_ucs2 (const update_req_t *update_req, uint16_t **name)
{
  if (update_req->label_size % 2 != 0)
    {
      prlog (PR_ERR, "label has an odd number of bytes: %lu\n",
             (unsigned long) update_req->label_size);
      return SV_LABEL_IS_NOT_WIDE_CHARACTERS;
    }

  /* zero-terminate the name */
  *name = (uint16_t *) libstb_zalloc (update_req->label_size + 2);
  if (*name == NULL)
    {
      prlog (PR_ERR, "failed to allocate memory for UCS-2 name!");
      return SV_ALLOCATION_FAILED;
    }

  memcpy (*name, update_req->label, update_req->label_size);

  return SV_SUCCESS;
}

/*
 * unpack our variables. if something goes wrong in unpacking this is fatal,
 * unless we happen to be replacing the variable
 */
static sv_err_t
unpack_current_var (const update_req_t *update_req, auth_data_t *auth_data)
{
  sv_err_t rc = SV_SUCCESS;

  if (update_req->current_data != NULL && update_req->current_data_size != 0)
    {
      rc = unpack_signed_var (update_req->current_data, update_req->current_data_size,
                              &auth_data->current_esl_data, &auth_data->current_esl_data_size,
                              auth_data->current_time);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_WARNING, "Cannot unpack current variable SV\n");
          if (!update_req->append_update)
            {
              auth_data->current_esl_data = NULL;
              auth_data->current_esl_data_size = 0;
              auth_data->current_time = NULL;
              rc = SV_SUCCESS;
            }
        }
    }

  return rc;
}

static sv_err_t
unpack_authdb (const update_req_t *update_req, const uint16_t *name, auth_data_t *auth_data)
{
  sv_err_t rc = SV_SUCCESS;
  timestamp_t dummy_time = { 0 };
  auth_db_t *auth_db = (auth_db_t *) &update_req->auth_db;

  if (auth_db->pk != NULL && auth_db->pk_size != 0)
    {
      rc = unpack_signed_var (auth_db->pk, auth_db->pk_size, &auth_data->auth_db.pk,
                              &auth_data->auth_db.pk_size, &dummy_time);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_WARNING, "Cannot unpack PK SV\n");
          if (wide_str_equals (name, (const uint16_t *) &global_variable[0]) &&
              update_req->allow_unauthenticated)
            {
              /* we permit this as a recovery technique */
              auth_data->auth_db.pk = NULL;
              rc = SV_SUCCESS;
            }
          else
            return rc;
        }
    }

  if (auth_db->kek != NULL && auth_db->kek_size != 0)
    {
      rc = unpack_signed_var (auth_db->kek, auth_db->kek_size, &auth_data->auth_db.kek,
                              &auth_data->auth_db.kek_size, &dummy_time);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_WARNING, "Cannot unpack KEK SV\n");
          if (wide_str_equals (name, (const uint16_t *) &global_variable[1]) &&
              !update_req->append_update)
            {
              auth_data->auth_db.kek = NULL;
              rc = SV_SUCCESS;
            }
          else
            return rc;
        }
    }

  return rc;
}

static bool
is_global_variable (const uint16_t *name)
{
  int i = 0;
  size_t len = sizeof (global_variable) / sizeof (global_variable[0]);

  for (i = 0; i < len; i++)
    {
      if (wide_str_equals (name, (const uint16_t *) &global_variable[i]))
        return true;
    }

  return false;
}

static bool
is_security_variable (uint16_t *name)
{
  int i = 0;
  size_t len = sizeof (security_variable) / sizeof (security_variable[0]);

  for (i = 0; i < len; i++)
    {
      if (wide_str_equals (name, (const uint16_t *) &security_variable[i]))
        return true;
    }

  return false;
}

/* derive our vendor GUID */
uuid_t *
get_guid (uint16_t *name)
{
  if (is_global_variable (name))
    return (uuid_t *) &SV_GLOBAL_VARIABLE_GUID;
  else if (is_security_variable (name))
    return (uuid_t *) &SV_IMAGE_SECURITY_DATABASE_GUID;

  return (uuid_t *) &POWER_VENDOR_GUID;
}

/* special wipe update */
static sv_err_t
is_wipe_update (const bool allow_unauthenticated, const uint8_t *new_esl_data,
                const size_t new_esl_data_size, const bool is_pk)
{
  sv_err_t rc = SV_SUCCESS;

  if (is_pk && (new_esl_data_size - ESL_HEADER_SIZE) == strlen (WIPE_SB_MAGIC) &&
      memcmp (new_esl_data + ESL_HEADER_SIZE, WIPE_SB_MAGIC,
              (new_esl_data_size - ESL_HEADER_SIZE)) == 0)
    {
      if (allow_unauthenticated)
        rc = SV_DELETE_EVERYTHING;
      else
        {
          prlog (PR_ERR, "Will not wipe variables unless allow unauthenticated "
                         "PK update is set.\n");
          rc = SV_INVALID_PK_UPDATE;
        }
    }

  return rc;
}

static sv_err_t
validate_cert (const uint8_t *new_esl_data, const size_t new_esl_data_size,
               const bool check_CA, const bool is_pk)
{
  sv_err_t rc = SV_SUCCESS;
  const uint8_t *cert_data = NULL, *tmp = NULL;
  size_t cert_size = 0;
  uuid_t cert_owner = { 0 };

  /* this may be either nothing or a list of RSA-2048 certs in ESLs */
  rc = next_cert_from_esls_buf (new_esl_data, new_esl_data_size,
                                &cert_data, &cert_size, &cert_owner, &tmp);
  while (rc == SV_SUCCESS && cert_data != NULL)
    {
      if (!cert_parses_as_good_RSA (cert_data, cert_size, check_CA))
        return SV_X509_ERROR;

      rc = next_cert_from_esls_buf (new_esl_data, new_esl_data_size,
                                    &cert_data, &cert_size, &cert_owner, &tmp);
      if (is_pk && (rc != SV_SUCCESS || cert_data != NULL))
        {
          prlog (PR_ERR, "it contained multiple certs or trailing data\n");
          return SV_INVALID_PK_UPDATE;
        }
    }

  return rc;
}

static sv_err_t
validate_trustedcadb_cert (const uint8_t *new_esl_data, const size_t new_esl_data_size,
                           const uint16_t *name)
{
  sv_err_t rc = SV_SUCCESS;

  if (!wide_str_equals (name, (const uint16_t *) &security_variable[6]))
    return rc;

  if (new_esl_data_size != 0)
    {
      rc = validate_cert (new_esl_data, new_esl_data_size, true, false);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "trustedcadb update failed (%d)\n", rc);
          return SV_INVALID_TRUSTEDCADB_UPDATE;
        }
    }

  return rc;
}

/*
 * If PK, verify that this is an ESL with an RSA-2048 cert
 */
static sv_err_t
validate_pk_cert (const uint8_t *new_esl_data, const size_t new_esl_data_size,
                  const bool is_pk)
{
  sv_err_t rc = SV_SUCCESS;

  if (!is_pk)
    return SV_INVALID_PK_UPDATE;

  if (new_esl_data_size != 0)
    {
      rc = validate_cert (new_esl_data, new_esl_data_size, false, is_pk);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "PK update failed (%d)\n", rc);
          return SV_INVALID_PK_UPDATE;
        }
    }

  return rc;
}

/*
 * If KEK, verify that this is empty or a set of ESLs with RSA-2048 certs
 */
static sv_err_t
validate_kek_cert (const uint8_t *new_esl_data, const size_t new_esl_data_size,
                   const uint16_t *name)
{
  sv_err_t rc = SV_SUCCESS;

  if (!wide_str_equals (name, (const uint16_t *) &global_variable[1]))
    return rc;

  if (new_esl_data_size != 0)
    {
      rc = validate_cert (new_esl_data, new_esl_data_size, false, false);
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "KEK update failed (%d)\n", rc);
          return SV_INVALID_KEK_UPDATE;
        }
    }

  return rc;
}

/*
 * Apply an update based on pseries rules.
 *
 * @label/@label_size: variable name
 * @allow_unauthenticated_pk_update: allow an unauthenticated PK update?
 * @append_update: is this an append?
 * @update_data: message data
 * @update_data_size: message data length
 * @current_data/@current_data_size: current var contents, or NULL/0
 * @pk_data/@pk_data_size: the current contents of the PK variable, or NULL/0
 * @kek_data/@kek_data_size: contents of KEK variable or NULL/0
 * @new_data/@new_esl_data_size: out
 *
 * If new_esl_data_size is 0, new_data will be NULL. This represents variable deletion.
 * return code: SUCCESS if the update was valid, otherwise an error code.
 *
 * Lifetime: new_data is a fresh allocation if rc = SUCCESS. Caller must free with libstb_free().
 */
sv_err_t
pseries_update_variable (const update_req_t *update_req, uint8_t **new_esl_data,
                         size_t *new_esl_data_size)
{
  sv_err_t rc = SV_SUCCESS;
  bool is_pk = false;
  uint16_t *name = NULL;
  uint8_t *esl_data = NULL;
  size_t esl_data_size = 0;
  auth_data_t auth_data = { 0 };
  timestamp_t new_time = { 0 }, current_time = { 0 };
  sv_flag_t verified_flag;

  rc = convert_to_ucs2 (update_req, &name);
  if (rc != SV_SUCCESS)
    return rc;

  /*
   * verify that there are no embedded nuls. This is important because otherwise
   * the hash validation will take place on only a prefix of the name!
   */
  if (wide_strlen (name) * 2 != update_req->label_size)
    {
      prlog (PR_ERR, "label seems to have embedded UCS-2 nul\n");
      rc = SV_LABEL_IS_NOT_WIDE_CHARACTERS;
    }
  /* verify that PK does not get an update */
  else if ((is_pk = wide_str_equals (name, (const uint16_t *) &global_variable[0])) &&
           update_req->append_update)
      rc = SV_CANNOT_APPEND_TO_PK;
  else
    {
      auth_data.current_time = &current_time;
      rc = unpack_current_var (update_req, &auth_data);
      if (rc == SV_SUCCESS)
        rc = unpack_authdb (update_req, name, &auth_data);
    }

  if (rc != SV_SUCCESS)
    {
      libstb_free (name);
      return rc;
    }

  auth_data.name = name;
  auth_data.vendor = get_guid (name);
  auth_data.attributes = SECVAR_ATTRIBUTES |
                         (update_req->append_update ? SV_VARIABLE_APPEND_WRITE : 0);
  auth_data.flag = (update_req->allow_unauthenticated && is_pk ?
                    SV_VARIABLE_UPDATE_SKIP_VERIFICATION : SV_VARIABLE_UPDATE_NO_FLAGS);
  auth_data.auth_msg = update_req->update_data;
  auth_data.auth_msg_size = update_req->update_data_size;

  if (auth_data.current_esl_data == NULL)
    auth_data.current_time = NULL;

  /* apply the update */
  rc = pseries_apply_update (&auth_data, &esl_data, &esl_data_size, &new_time, &verified_flag);
  if (rc == SV_SUCCESS)
    {
      if ((verified_flag & SV_AUTH_VERIFIED_BY_PK) && esl_data_size != 0)
        {
          rc = is_wipe_update (update_req->allow_unauthenticated, esl_data,
                               esl_data_size, is_pk);
          if (rc == SV_SUCCESS)
            {
              rc = validate_pk_cert (esl_data, esl_data_size, is_pk);
              if (rc != SV_SUCCESS)
                rc = validate_kek_cert (esl_data, esl_data_size, name);
            }
        }
      else if (esl_data_size == 0)
        {
          *new_esl_data = NULL;
          *new_esl_data_size = 0;
        }

      if ((rc == SV_SUCCESS && (verified_flag & SV_AUTH_VERIFIED_BY_KEK) &&
          esl_data_size == 0) || (rc == SV_SUCCESS && esl_data_size != 0))
        {
          rc = validate_trustedcadb_cert (esl_data, esl_data_size, name);
          if (rc == SV_SUCCESS)
            {
              /* pack it */
              rc = pack_signed_var (esl_data, esl_data_size, &new_time, new_esl_data,
                                    new_esl_data_size);
              if (rc != SV_SUCCESS)
                prlog (PR_ERR, "Error packing new variable.\n");
            }
        }
    }
  else
    prlog (PR_ERR, "Failed to apply variable update.\n");

  libstb_free (esl_data);
  libstb_free (name);

  return rc;
}

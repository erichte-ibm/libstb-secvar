/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include <stdint.h>
#include <stddef.h>
#include "log.h"
#include "secvar/util.h"
#include "secvar/crypto.h"
#include "secvar/authentication_2.h"

/*
 * Unpack an authenticated variable update into:
 *  - a validated the EFI timestamp (in that the fixed bytes are zero
 *    TODO enforce limits on D,M,Y,H,M,S)
 *  - a PKCS#7 message
 *  - the data over which the signature is made.
 *
 * The result shall be either an error code describing the way in which the data
 * is unsuitable, or a set of data structures ready for signature verification.
 *
 * Successful return of the function implies that the authentication_2 structure
 * is valid but does not say anything about the PKCS#7 message.
 *
 * NB: it is possible for *data to point just past the end of buf and have
 * data_size = 0!
 *
 * Lifetime: outputs are just pointers into the input buffer, so they have the
 * same lifetime as the underlying buffer.
 */
sv_err_t
unpack_authenticated_variable (const auth_data_t *auth_data, timestamp_t *timestamp,
                               const uint8_t **cert_data, size_t *cert_size,
                               const uint8_t **data, size_t *data_size)
{
  const auth_info_t *auth = NULL;
  size_t da_length = 0, left = 0;

  if (auth_data->auth_msg_size < sizeof (auth_info_t))
    {
      prlog (PR_ERR, "Buffer too small for an auth2 header - got %lu bytes.\n",
             (unsigned long) auth_data->auth_msg_size);
      return SV_BUF_INSUFFICIENT_DATA;
    }

  auth = (auth_info_t *) auth_data->auth_msg;

  if (auth->timestamp.pad1 != 0 || auth->timestamp.nanosecond != 0 ||
      auth->timestamp.timezone != 0 || auth->timestamp.daylight != 0 ||
      auth->timestamp.pad2 != 0)
    {
      prlog (PR_ERR, "Timestamp reserved bytes were not NULL\n");
      return SV_AUTH_INVALID_FIXED_VALUE;
    }

  *timestamp = auth->timestamp;

  /*
   * avoiding under and overflow properly here is a bit tricky:
   * we know that we can fit the fixed bits, so left >= 0 now
   */
  left = auth_data->auth_msg_size - sizeof (auth_info_t);
  da_length = le32_to_cpu (auth->auth_cert.hdr.da_length);
  /*
   * da_length includes the header and should include the uuid in the
   * outer structure also
   */
  if (da_length <= sizeof (auth_cert_t))
    {
      prlog (PR_ERR, "da_length in auth header too short for fixed data - %lu bytes\n",
             (unsigned long) da_length);
      return SV_AUTH_SIZE_INVALID;
    }

  if (da_length - sizeof (auth_cert_t) > left)
    {
      prlog (PR_ERR,
             "da_length in auth header would run past the end of the buffer\n");
      return SV_AUTH_SIZE_INVALID;
    }

  /*
   * at this point we have that we can consume dw_length bytes
   * Check the other fields
   */
  if (auth->auth_cert.hdr.a_revision != CPU_TO_LE16 (0x0200))
    return SV_AUTH_UNSUPPORTED_REVISION;

  if (auth->auth_cert.hdr.a_certificate_type != CPU_TO_LE16 (AUTH_CERT_TYPE_GUID))
    {
      prlog (PR_ERR, "a_certificate_type in auth header is not AUTH_CERT_TYPE_EFI_GUID, instead got 0x%x\n",
             auth->auth_cert.hdr.a_certificate_type);
      return SV_AUTH_INVALID_FIXED_VALUE;
    }

  if (!uuid_equals (&auth->auth_cert.cert_type, &AUTH_CERT_TYPE_PKCS7_GUID))
    {
      prlog (PR_ERR, "Expecting a AUTH_CERT_TYPE_PKCS7_GUID in auth2 header, "
                     "got something else.\n");
      return SV_AUTH_INVALID_FIXED_VALUE;
    }

  /*auth certificate */
  *cert_data = auth->auth_cert.cert_data;
  *cert_size = da_length - sizeof (auth_cert_t);

  /* esl data */
  left -= *cert_size;
  *data = auth_data->auth_msg + sizeof (auth_info_t) + *cert_size;
  *data_size = left;

  return SV_SUCCESS;
}

/*
 * generate a hash for comparison with an auth2 signed structure
 *
 * @data: data portion of the message or NULL if there is no data
 * @data_size: size of the data if present.
 *
 * @hash: out: buffer containing the hash. To be allocated
 *
 * Returns: 0 on success, otherwise an error from the crypto library
 * (e.g. out of memory)
 *
 * Lifetime: output is expected to be storage managed by the caller.
 *
 * It isn't clear that SHA-256 should be the only supported hash algo but
 * construction of the authentication_2 structure makes it clear that only
 * SHA-256 is acceptable, so this generates a SHA-256 hash unconditionally.
 */
sv_err_t
construct_auth2_hash (const auth_data_t *auth_data, const timestamp_t *timestamp,
                      const uint8_t *data, const size_t data_size, uint8_t **hash)
{
  sv_err_t rc = SV_SUCCESS;
  size_t name_len = 0, hash_len = 0, len = 0;
  uint8_t *auth_msg = NULL;
  uint32_t le_attributes = cpu_to_le32 (auth_data->attributes);

  /* don't rely on anyone being able to provide us with a wchar typed strlen */
  while (auth_data->name[name_len] != 0)
    name_len++;

  len = (name_len * 2) + sizeof (uuid_t) + sizeof (uint32_t) +
        sizeof (timestamp_t) + data_size;

  auth_msg = (uint8_t *) libstb_zalloc (len);
  if (auth_msg == NULL)
    return SV_ALLOCATION_FAILED;

  len = 0;
  memcpy (auth_msg + len, (uint8_t *) auth_data->name, name_len * 2);
  len += name_len * 2;
  memcpy (auth_msg + len, (uint8_t *) auth_data->vendor, sizeof (uuid_t));
  len += sizeof (uuid_t);
  memcpy (auth_msg + len, (uint8_t *) &le_attributes, sizeof (uint32_t));
  len += sizeof (uint32_t);
  memcpy (auth_msg + len, (uint8_t *) timestamp, sizeof (timestamp_t));
  len += sizeof (timestamp_t);

  if (data != NULL)
    {
      memcpy (auth_msg + len, data, data_size);
      len += data_size;
    }

  rc = crypto_md_generate_hash (auth_msg, len, CRYPTO_MD_SHA256, hash, &hash_len);
  if (rc != SV_SUCCESS)
    {
      prlog (PR_ERR, "auth2 hash generation failed\n");
    }

  libstb_free (auth_msg);

  return rc;
}

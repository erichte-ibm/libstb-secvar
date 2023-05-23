/*
 *SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "secvar/esl.h"
#include "secvar/util.h"
#include "log.h"
#include "libstb-secvar-errors.h"

/*
 * do the internal sizes reported by an ESL make sense?
 *   - does total size = sizeof(ESL) + signature header + n * (signature size)?
 *     for n >= 1
 *   - does signature size fit an ESD?
 *
 * Assumes ESL->signature_list_size fits within the buffer!
 */
static bool
esl_internal_sizes_sensible (const sv_esl_t *esl)
{
  size_t claimed_size, sighdr_size, sig_size;

  claimed_size = le32_to_cpu (esl->signature_list_size);
  sighdr_size = le32_to_cpu (esl->signature_header_size);
  sig_size = le32_to_cpu (esl->signature_size);

  if (sighdr_size > claimed_size - sizeof (sv_esl_t))
    return false;
  else if (sig_size > claimed_size - sizeof (sv_esl_t) - sighdr_size)
    return false;
  /* use <= to require at least 1 byte of sig! */
  else if (sig_size <= sizeof (sv_esd_t))
    return false;
  else if ((claimed_size - sizeof (sv_esl_t) - sighdr_size) % sig_size != 0)
    return false;

  return true;
}

/*
 * next_esl_from_buffer: given the current ESL or NULL, what's the next
 * valid and complete ESL within the buffer?
 *
 * @buf: input buffer
 * @buf_size: how big is @buf?
 *
 * @esl: pointer to pointer to esl data.
 *     in: pointer to the current ESL or NULL if you're at the beginning.
 *     out: pointer to the next ESL or NULL if there's no subsequent ESL.
 *
 *  @esl_size: out: size of the next esl
 *
 * Returns: 0 on success, otherwise an error code.
 *
 * Lifetimes: esl is a pointer into buf, so the lifetime is that of the
 * containing buffer.
 */
sv_err_t
next_esl_from_buffer (const uint8_t *buf, size_t buf_size, const uint8_t **esl,
                      size_t *esl_size)
{
  const uint8_t *pos;
  size_t left, claimed_size;
  const sv_esl_t *cur, *next;
  bool first;

  if (buf == NULL || esl == NULL || esl_size == NULL)
    return SV_BUF_INSUFFICIENT_DATA;

  if (*esl != NULL && ((*esl < buf) || (*esl > (buf + buf_size))))
    return SV_BUF_INSUFFICIENT_DATA;

  first = (*esl == NULL);

  if (first)
    {
      pos = buf;
      left = buf_size;
    }
  else
    {
      pos = *esl;
      left = buf_size - (*esl - buf);
    }

  *esl = NULL;

  if (left < sizeof (sv_esl_t))
    {
      prlog (PR_ERR, "Not enough space left for an ESL when unpacking buffer: %lu bytes remain\n",
             left);
      return SV_BUF_INSUFFICIENT_DATA;
    }

  /* Attempt to read the current ESL */
  cur = (sv_esl_t *) pos;

  claimed_size = le32_to_cpu (cur->signature_list_size);
  if (claimed_size < sizeof (sv_esl_t))
    {
      prlog (PR_ERR, "ESL's claimed size is too small for the fixed contents: %lu bytes\n",
             claimed_size);
      return SV_ESL_SIZE_INVALID;
    }
  else if (claimed_size > left)
    {
      prlog (PR_ERR, "ESL's claimed size is bigger than the data left in the buffer: %lu vs %lu\n",
             claimed_size, left);
      return SV_BUF_INSUFFICIENT_DATA;
    }

  if (!esl_internal_sizes_sensible (cur))
    {
      prlog (PR_ERR, "ESL's internal sizes are not OK\n");
      return SV_ESL_SIZE_INVALID;
    }

  /*
   * If we want the first ESL, we are done. Otherwise we need to skip
   * over the current ESL to the next one.
   */
  if (first)
    {
      *esl = pos;
      *esl_size = claimed_size;
      return SV_SUCCESS;
    }

  pos += claimed_size;
  left -= claimed_size;

  /*
   * We only return NULL and success if we use up all the data
   * exactly. If there's any trailing data, we return an error.
   */
  if (left == 0)
    {
      /* esl NULLed out above */
      return SV_SUCCESS;
    }
  else if (left < sizeof (sv_esl_t))
    {
      prlog (PR_ERR, "Trailing data in buffer, not enough for an ESL\n");
      return SV_BUF_INSUFFICIENT_DATA;
    }

  next = (sv_esl_t *) pos;

  claimed_size = le32_to_cpu (next->signature_list_size);
  if (claimed_size < sizeof (sv_esl_t))
    {
      prlog (PR_ERR, "ESL's claimed size is too small for the fixed contents: %lu bytes\n",
             claimed_size);
      return SV_ESL_SIZE_INVALID;
    }
  else if (claimed_size > left)
    {
      prlog (PR_ERR, "ESL's claimed size is bigger than the data left in the buffer: %lu vs %lu\n",
             claimed_size, left);
      return SV_BUF_INSUFFICIENT_DATA;
    }

  if (!esl_internal_sizes_sensible (next))
    {
      prlog (PR_ERR, "ESL's internal sizes are not OK\n");
      return SV_ESL_SIZE_INVALID;
    }

  *esl = pos;
  *esl_size = claimed_size;
  return SV_SUCCESS;
}

/*
 * next_esd_from_esl_buffer: given the current ESD or NULL, what's the next
 * valid and complete ESD within the buffer?
 *
 * @esl: input buffer, containing a valid and complete ESL - that is, containing
 *       at least as many bytes as declared in the ESL.
 *
 * @esd_data: pointer to pointer to esd signature data.
 *     in: pointer to the current data or NULL if you're at the beginning.
 *     out: pointer to the next ESD data or NULL if there's no subsequent ESD.
 *
 * @esd_data_size: out: size of the next esd *data* (exclusive of UUID)
 * @esd_owner: out: signature_owner, set if there's a valid ESD.
 *
 * Returns: 0 on success, otherwise an error code.
 *
 * Lifetimes: esd_data is a pointer into esl, so the lifetime is that of the
 * containing buffer.
 */
sv_err_t
next_esd_from_esl (const uint8_t *esl, const uint8_t **esd_data, size_t *esd_data_size,
                   uuid_t *esd_owner)
{
  sv_esl_t *esl_struct;
  sv_esd_t *cur, *next;
  bool first;
  const uint8_t *posp;
  size_t pos, left, esl_size, esd_size, esl_shs;

  if (esl == NULL)
    return SV_BUF_INSUFFICIENT_DATA;

  esl_struct = (sv_esl_t *) esl;
  esl_size = le32_to_cpu (esl_struct->signature_list_size);
  esd_size = le32_to_cpu (esl_struct->signature_size);
  esl_shs = le32_to_cpu (esl_struct->signature_header_size);

  if (esd_data == NULL || esd_data_size == NULL)
    return SV_BUF_INSUFFICIENT_DATA;

  if (*esd_data != NULL && ((*esd_data < esl) && (*esd_data > (esl + esl_size))))
    return SV_BUF_INSUFFICIENT_DATA;

  first = (*esd_data == NULL);

  if (first)
    {
      posp = esl + sizeof (sv_esl_t) + esl_shs;
      pos = sizeof (sv_esl_t) + esl_shs;
    }
  else
    {
      /* reverse to start of ESD */
      posp = *esd_data - sizeof (sv_esd_t);
      pos = posp - esl;
    }
  left = esl_size - pos;

  /* this _should_ be safe given the checks before but just in case */
  if (left < esd_size)
    {
      prlog (PR_ERR, "Not enough space in ESL for an ESD\n");
      return SV_ESL_SIZE_INVALID;
    }

  *esd_data = NULL;

  cur = (sv_esd_t *) posp;

  if (first)
    {
      *esd_data = cur->signature_data;
      *esd_data_size = esd_size - sizeof (sv_esd_t);
      *esd_owner = cur->signature_owner;
      return SV_SUCCESS;
    }

  posp += esd_size;
  left -= esd_size;

  /* do not allow trailing data */
  if (left == 0)
    {
      /* nulled out esd_data above */
      return SV_SUCCESS;
    }
  /* this _should_ be safe given the checks before but just in case */
  else if (left < esd_size)
    {
      prlog (PR_ERR, "Trailing bytes but not enough space for another ESD.");
      return SV_ESL_SIZE_INVALID;
    }
  next = (sv_esd_t *) posp;
  *esd_data = next->signature_data;
  *esd_data_size = esd_size - sizeof (sv_esd_t);
  *esd_owner = next->signature_owner;

  return SV_SUCCESS;
}

/*
 * next_cert_from_esls_buffer: given the current certificate or NULL, what's the
 * next certificate within the buffer of ESLs?
 *
 * @buf: input buffer, expected to contain ESLs of PKS_CERT_X509_GUID.
 * @buf_size: how big is @buf?
 *
 * @cert: pointer to pointer to certificate data.
 *     in: pointer to the current cert or NULL if you're at the beginning.
 *     out: pointer to the next cert or NULL if there's no subsequent cert.
 *
 * @cert_size: out: size of the next esl
 *
 * @cert_owner: out: UUID representing certificate owner.
 *
 * @esl: in/out: opaque storage for internal state. Pass in storage for 1
 * uint8_t pointer.
 *
 * Returns: 0 on success, otherwise an error code.
 *
 * Lifetimes: cert is a pointer into buf, so the lifetime is that of the
 * containing buffer.
 */
sv_err_t
next_cert_from_esls_buf (const uint8_t *buf, size_t buf_size, const uint8_t **cert,
                         size_t *cert_size, uuid_t *cert_owner, const uint8_t **esl)
{
  const sv_esl_t *esl_struct;
  size_t esl_size;
  sv_err_t rc;
  bool first;

  if (!buf || !cert || !cert_size || !cert_owner || !esl)
    return SV_BUF_INSUFFICIENT_DATA;

  first = (*cert == NULL);

  /*
   * try to fetch the next ESD from the ESL. There will probably never
   * be 2 of the same size in a single ESD, but it _could_ happen.
   */
  if (first)
    {
      *esl = NULL;
    }
  else
    {
      rc = next_esd_from_esl (*esl, cert, cert_size, cert_owner);

      if (rc)
        {
          /* trust function to log themselves */
          return rc;
        }
    }

  /*
   * we have reached the end of the ESL (or we are at the start and haven't
   * got our first ESL yet.)
   */
  if (*cert == NULL)
    {
      rc = next_esl_from_buffer (buf, buf_size, esl, &esl_size);
      if (rc)
        return rc;

      if (!*esl)
        {
          *cert = NULL;
          return SV_SUCCESS;
        }

      esl_struct = (sv_esl_t *) *esl;
      if (!uuid_equals (&esl_struct->signature_type, &PKS_CERT_X509_GUID))
        {
          prlog (PR_ERR, "Found ESL, but it's not an PKS_CERT_X509_GUID\n");
          return SV_ESL_WRONG_TYPE;
        }
    }

  rc = next_esd_from_esl (*esl, cert, cert_size, cert_owner);

  return rc;
}

/*
 * Helper function. We have found 2 ESLs with matching signature type, copy/size the merge.
 */
static sv_err_t
merge_esds_in_esl (const uint8_t *cur_esl_data, size_t cur_esl_data_size,
                   const uint8_t *update_esl_data, uint8_t *out_buf, size_t *out_buf_size)
{
  /* quadratic in ESD count, see merge_esls */
  sv_err_t rc;
  uuid_t update_esd_owner, cur_esd_owner;
  const uint8_t *update_esd_data, *cur_esd_data;
  size_t update_esd_data_size, cur_esd_data_size;
  size_t new_data_size = 0;
  uint8_t *out_ptr = out_buf;
  sv_esl_t *out_esl = (sv_esl_t *) out_buf;

  /* copy the current ESL to the output */
  new_data_size = cur_esl_data_size;
  if (out_buf)
    {
      if (*out_buf_size < cur_esl_data_size)
        {
          prlog (PR_ERR, "output buffer too small for current ESL data");
          return SV_OUT_BUF_TOO_SMALL;
        }
      memcpy (out_buf, cur_esl_data, cur_esl_data_size);
      out_ptr += cur_esl_data_size;
    }

  /*
   * for each ESD in the update
   * ... for each ESD in current
   * ... ... do they match?
   * ... if no match, copy it to the output
   */
  update_esd_data = NULL;
  rc = next_esd_from_esl (update_esl_data, &update_esd_data,
                          &update_esd_data_size, &update_esd_owner);

  while (rc == SV_SUCCESS && update_esd_data)
    {
      bool found_esd = false;
      cur_esd_data = NULL;

      rc = next_esd_from_esl (cur_esl_data, &cur_esd_data, &cur_esd_data_size, &cur_esd_owner);

      while (rc == SV_SUCCESS && cur_esd_data)
        {
          if (cur_esd_data_size == update_esd_data_size &&
              uuid_equals (&cur_esd_owner, &update_esd_owner) &&
              memcmp (cur_esd_data, update_esd_data, cur_esd_data_size) == 0)
            {
              found_esd = true;
              break;
            }

          rc = next_esd_from_esl (cur_esl_data, &cur_esd_data,
                                  &cur_esd_data_size, &cur_esd_owner);
        }
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "Error enumerating ESDs\n");
          return rc;
        }

      if (!found_esd)
        {
          new_data_size += sizeof (sv_esd_t) + update_esd_data_size;
          if (out_buf)
            {
              sv_esd_t *esd;

              if (*out_buf_size < new_data_size)
                {
                  prlog (PR_ERR, "output buffer too small for new ESD data");
                  return SV_OUT_BUF_TOO_SMALL;
                }

              esd = (sv_esd_t *) out_ptr;
              memcpy (&esd->signature_owner, &update_esd_owner, sizeof (uuid_t));
              memcpy (&esd->signature_data, update_esd_data, update_esd_data_size);
              out_ptr += sizeof (sv_esd_t) + update_esd_data_size;
            }
        }

      rc = next_esd_from_esl (update_esl_data, &update_esd_data,
                              &update_esd_data_size, &update_esd_owner);
    }
  if (rc != SV_SUCCESS)
    {
      prlog (PR_ERR, "Error enumerating ESDs\n");
      return rc;
    }

  *out_buf_size = new_data_size;
  if (new_data_size > 0xffffffffUL)
    {
      prlog (PR_ERR, "Resultant ESL would be too large to store in "
                     "signature_list_size\n");
      return SV_TOO_MUCH_DATA;
    }
  if (out_buf)
    out_esl->signature_list_size = cpu_to_le32 (new_data_size);
  return SV_SUCCESS;
}

/* handle DO_NOT_MERGE_CERTIFICATE_ESLS while preserving append(x, x) == x */
static inline bool
can_merge_esls (const sv_esl_t *a, const sv_esl_t *b)
{
  bool result = uuid_equals (&a->signature_type, &b->signature_type);

#ifdef DO_NOT_MERGE_CERTIFICATE_ESLS
  if (result && uuid_equals (&a->signature_type, &PKS_CERT_X509_GUID))
    {
      result = (a->signature_list_size == b->signature_list_size &&
                memcmp ((const uint8_t *) a, (const uint8_t *) b,
                        le32_to_cpu (a->signature_list_size)) == 0);
    }
#endif

  return result;
}

/*
 * Merge 2 ESL buffers
 * Applying an append update is not as trivial as the name suggests for an
 * EFI_IMAGE_SECURITY_DATABASE variable (db, dbx) because we're supposed to
 * de-duplicate entries: s 8.2.2:
 *
 * For variables with the GUID EFI_IMAGE_SECURITY_DATABASE_GUID (i.e. where the
 * data buffer is formatted as sv_esl_t), the driver shall not
 * perform an append of sv_esd_t values that are already part of the
 * existing variable value.
 *
 * @cur_buf: current variable data, expected to be a series of ESLs.
 * @cur_buf_size: size
 * @update_buf: update data, expected to be a series of ESLs.
 * @update_buf_size: size
 * @out_buf: out: buffer to write data to or NULL, see Notes
 * @out_buf_size: in: size of buffer
 *               out: bytes written/required (see Notes)

 * Notes: If called with a NULL out buffer, sets out size and return success
 * without copying data. Otherwise, updates out_buf_size with the number of bytes
 * written.
 *
 * Returns: 0 on success, otherwise an error code.
 *
 * Lifetime: copies data from inputs to output, no internal allocations.
 */
sv_err_t
merge_esls (const uint8_t *cur_buf, size_t cur_buf_size, const uint8_t *update_buf,
            size_t update_buf_size, uint8_t *out_buf, size_t *out_buf_size)
{
  /*
   * This is quadratic in the number of ESLs and ESDs. That shouldn't matter
   * given the limitations on how many we can feasibly have, and allows us
   * to avoid a bunch of internal allocations. But beware if things suddenly scale.
   */

  size_t new_data_size = 0;
  sv_err_t rc;
  const uint8_t *update_esl_data, *cur_esl_data;
  size_t update_esl_size, cur_esl_size;
  const sv_esl_t *cur_esl, *update_esl;
  uint8_t *out_ptr = out_buf;

  /*
   * this is a bit inefficient but it doesn't require
   * dynamic allocations and we expect the data set to be small.
   *
   * for each ESL in current
   * ... for each ESL in the update
   * ... ... do they match?
   * ... if match, so merge to output
   * ... if no match, copy it to the output
   *
   * for each ESL in the update
   * ... for each ESL in current
   * ... ... do they match?
   * ... if no match, copy it to the output
   */
  cur_esl_data = NULL;
  rc = next_esl_from_buffer (cur_buf, cur_buf_size, &cur_esl_data, &cur_esl_size);
  /* for each ESL in current */
  while (rc == SV_SUCCESS && cur_esl_data)
    {
      bool found_esl = false;
      cur_esl = (sv_esl_t *) cur_esl_data;

      update_esl_data = NULL;
      rc = next_esl_from_buffer (update_buf, update_buf_size, &update_esl_data, &update_esl_size);

      /* for each update */
      while (rc == SV_SUCCESS && update_esl_data)
        {
          update_esl = (sv_esl_t *) update_esl_data;

          if (can_merge_esls (cur_esl, update_esl))
            {
              /* we've found a matching ESL. merge in updated */
              found_esl = true;
              break;
            }

          rc = next_esl_from_buffer (update_buf, update_buf_size,
                                     &update_esl_data, &update_esl_size);
        }
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "Error enumerating ESLs\n");
          return rc;
        }

      if (found_esl)
        {
          /* merge in */
          size_t req_size = *out_buf_size - new_data_size;
          rc = merge_esds_in_esl (cur_esl_data, cur_esl_size, update_esl_data,
                                  out_ptr, &req_size);
          if (rc != SV_SUCCESS)
            return rc;
          new_data_size += req_size;
          if (out_buf)
            out_ptr += req_size;
        }
      else
        {
          /* copy across */
          new_data_size += cur_esl_size;
          if (out_buf)
            {
              if (new_data_size > *out_buf_size)
                {
                  prlog (PR_ERR,
                         "Not enough space in output buffer to copy ESL in.\n");
                  return SV_OUT_BUF_TOO_SMALL;
                }
              memcpy (out_ptr, cur_esl_data, cur_esl_size);
              out_ptr += cur_esl_size;
            }
        }

      rc = next_esl_from_buffer (cur_buf, cur_buf_size, &cur_esl_data, &cur_esl_size);
    }
  if (rc != SV_SUCCESS)
    {
      prlog (PR_ERR, "Error enumerating ESLs");
      return rc;
    }

  /* copy in any ESLs from the update that are not in current */
  update_esl_data = NULL;
  rc = next_esl_from_buffer (update_buf, update_buf_size, &update_esl_data, &update_esl_size);

  /* for each update */
  while (rc == SV_SUCCESS && update_esl_data)
    {
      /* is there a current ESL with the same GUID? */
      bool found_esl = false;

      update_esl = (sv_esl_t *) update_esl_data;

      cur_esl_data = NULL;
      rc = next_esl_from_buffer (cur_buf, cur_buf_size, &cur_esl_data, &cur_esl_size);
      while (rc == SV_SUCCESS && cur_esl_data)
        {
          cur_esl = (sv_esl_t *) cur_esl_data;

          if (can_merge_esls (cur_esl, update_esl))
            {
              /* we've found a matching ESL. we have already copied/merged, ignore. */
              found_esl = true;
              break;
            }
          rc = next_esl_from_buffer (cur_buf, cur_buf_size, &cur_esl_data, &cur_esl_size);
        }
      if (rc != SV_SUCCESS)
        {
          prlog (PR_ERR, "Error enumerating ESLs");
          return rc;
        }

      /* an ESL only in update. copy in. */
      if (!found_esl)
        {
          new_data_size += update_esl_size;
          if (out_buf)
            {
              if (*out_buf_size < new_data_size)
                {
                  prlog (PR_ERR,
                         "Not enough space in output buffer to copy in ESL.\n");
                  return SV_OUT_BUF_TOO_SMALL;
                }
              memcpy (out_ptr, update_esl_data, update_esl_size);
              out_ptr += update_esl_size;
            }
        }

      rc = next_esl_from_buffer (update_buf, update_buf_size, &update_esl_data, &update_esl_size);
    }
  if (rc != SV_SUCCESS)
    {
      prlog (PR_ERR, "Error enumerating ESLs");
      return rc;
    }

  *out_buf_size = new_data_size;
  return SV_SUCCESS;
}

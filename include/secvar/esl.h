/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#ifndef __LIBSTB_SECVAR_ESL_H
#define __LIBSTB_SECVAR_ESL_H

#include <stdint.h>
#include <stddef.h>
#include <external/edk2/common.h>
#include "libstb-secvar-errors.h"

/*
 * If you have two certificates with the same size, should we combine them
 * into 1 ESL w/ 2 ESDs, or 2 ESLs each w/ 1 ESD?
 *
 * Certificates will 'normally' be in their own ESLs, but ESLs can sometimes
 * contain multiple.
 * Skiboot and skiboot derived tools cannot handle cert ESLs with multiple ESDs.
 */
#define DO_NOT_MERGE_CERTIFICATE_ESLS

/*
 * next_esl_from_buffer: given the current ESL or NULL, what's the next
 * valid and complete ESL within the buffer?
 *
 * @buf: input buffer
 * @buf_size: how big is @buf?
 *
 * @esl: pointer to pointer to esl data.
 *     in: pointer to the current ESL or NULL if you're at the beginning.
 *    out: pointer to the next ESL or NULL if there's no subsequent ESL.
 *
 * @esl_size: out: size of the next esl
 *
 * Returns: 0 on success, otherwise an error code.
 *
 * Lifetimes: esl is a pointer into buf, so the lifetime is that of the
 * containing buffer.
 */
sv_err_t
next_esl_from_buffer (const uint8_t *buf, size_t buf_size, const uint8_t **esl,
                      size_t *esl_size);

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
 *
 * @esd_owner: out: SignatureOwner, set if there's a valid ESD.
 *
 * Returns: 0 on success, otherwise an error code.
 *
 * Lifetimes: esd_data is a pointer into esl, so the lifetime is that of the
 * containing buffer.
 */
sv_err_t
next_esd_from_esl (const uint8_t *esl, const uint8_t **esd_data, size_t *esd_data_size,
                   uuid_t *esd_owner);

/*
 * next_cert_from_esls_buffer: given the current certificate or NULL, what's the
 * next certificate within the buffer of ESLs?
 *
 * @buf: input buffer, expected to contain ESLs of EFI_CERT_X509_GUID.
 * @buf_size: how big is @buf?
 *
 * @cert: pointer to pointer to certificate data.
 *    in: pointer to the current cert or NULL if you're at the beginning.
 *   out: pointer to the next cert or NULL if there's no subsequent cert.
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
                         size_t *cert_size, uuid_t *cert_owner, const uint8_t **esl);

/*
 * Merge 2 ESL buffers
 * Applying an append update is not as trivial as the name suggests for an
 * EFI_IMAGE_SECURITY_DATABASE variable (db, dbx) because we're supposed to
 * de-duplicate entries: s 8.2.2:
 *
 * For variables with the GUID EFI_IMAGE_SECURITY_DATABASE_GUID (i.e. where the
 * data buffer is formatted as EFI_SIGNATURE_LIST), the driver shall not
 * perform an append of EFI_SIGNATURE_DATA values that are already part of the
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
            size_t update_buf_size, uint8_t *out_buf, size_t *out_buf_size);

#endif

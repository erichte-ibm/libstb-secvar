/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#ifndef __LIBSTB_SECVAR_AUTHENTICATION_2_H
#define __LIBSTB_SECVAR_AUTHENTICATION_2_H

#include <stdint.h>
#include <stddef.h>
#include <external/edk2/common.h>
#include "libstb-secvar-errors.h"

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
                               const uint8_t **data, size_t *data_size);
/*
 * generate a hash for comparison with an auth2 signed structure
 *
 * @data: data portion of the message or NULL if there is no data
 * @data_size: size of the data if present.
 *
 * @hash: out: buffer containing the hash. Allocated inside function
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
                      const uint8_t *data, const size_t data_size, uint8_t **hash);
#endif

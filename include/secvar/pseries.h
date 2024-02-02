/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
*/
/*
 * Here we wrap the EDK2-like primitives in
   something that has the pseries quirks. Quirks such as:
 *
 * - UUIDs are determined by looking at the name. The names PK, KEK, db, dbx
 *   and get their UUIDs from existing implementations and the
 *   shim respectively. Other variables are all inside a single UUID namespace.
 *
 * - The attributes are always 0x27 or 0x67. (NV BS RT TBAW and optionally
 *   APPEND). There is no PKS policy bit for these so will need to come via a
 *   separate input (e.g. the first byte of the data submitted to the kernel).
 *
 * - There's no setup mode but rather a magic switch that allows you to do
 *    unauthenticated PK updates only.
 *
 * - We have a special thing you can pass in to PK, which _must_ be called with
 *   the unauthenticated PK update switch on, which tells the upper layer to
 *   delete all signed variables. This is for migrating back towards a system
 *   that doesn't support signed variables.
 *
 * - We do not allow PK to be empty (except in the case above). We require PK to
 *   contain 1 and only 1 ESL, containing 1 certificate.
 *
 * - We do not allow append updates to PK. (That would break the 1 certificate
 *   rule.)
 *
 * - This means that the following pieces of info fully determine SB state:
 *    - ibm,secure-boot: is SB enforced or not
 *    - SB_VERSION: are static keys or dynamic keys used for SB?
 *
 * - Names come to us uint8_t sequences + length - unlike EDK2 where they are
 *   UCS-2 character strings - that is 16-bits per character and with a 0-valued
 *   character terminator (C strings but with "char" being 16-bit). We therefore
 *   have to deal with:
 *
 * - PKS labels may have odd-numbered bytes: reject attempt
 *   to create such a signed var.
 *
 * - PKS labels may contain any number of consecutive embedded nul/0 bytes:
 *   reject a name that contains an embedded 16-bit nul character - e.g.
 *   P\0\0\0K\0 (but permit P\0\0K).
 *
 * - PKS objects representing signed variables come wrapped in a metadata
 *   structure in order to store their timestamps. The current value of the
 *   variable being updated, and the PK and KEK variables passed to this function
 *   are expected to include this metadata, and the resulting data from this
 *   function will include metadata (unless the variable is being deleted).
 *
 * - We require that PK and KEK contain only RSA-2048 or RSA-4096 certificates,
 *   otherwise we reject the update. (This is enforced at time of use in
 *   update.c; this checks it at time of update too.)
 *
 */

#ifndef __LIBSTB_SECVAR_PSERIES_H
#define __LIBSTB_SECVAR_PSERIES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <external/edk2/common.h>
#include "crypto.h"
#include "libstb-secvar-errors.h"

/* UUID('36fd7583-986a-4b15-8228-041664342d51') */
static const uuid_t POWER_VENDOR_GUID = { { 0x83, 0x75, 0xfd, 0x36, 0x6a, 0x98,
                                            0x15, 0x4b, 0x82, 0x28, 0x04, 0x16,
                                            0x64, 0x34, 0x2d, 0x51 } };

#define SECVAR_ATTRIBUTES 39
#define WIPE_SB_MAGIC                                                    \
  "Yes, I want to delete all secure variables and reset secure boot to " \
  "static keys.\n"


struct var_hdr_timestamp
{
  leint16_t year;
  uint8_t month;
  uint8_t day;
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
} SV_PACKED;

struct signed_variable_header
{
  uint8_t version; /* must be 0 */
  struct var_hdr_timestamp timestamp;
} SV_PACKED;

/* derive our vendor GUID */
uuid_t *
get_guid (uint16_t *name);

/* Apply an update based on pseries rules.
 *
 * If new_data_size is 0, new_data will be NULL. This represents variable deletion.
 * return code: SUCCESS if the update was valid, otherwise an error code.
 *
 * Lifetime: new_data is a fresh allocation if SUCCESS. Caller must free with libstb_free().
 */
sv_err_t
pseries_update_variable (const update_req_t *updatereq, uint8_t **new_data,
                         size_t *new_data_size);
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
 * Lifetime: new_esl_data is a fresh allocation if rc = SUCCESS.
 * Caller must free with libstb_free().
 */
sv_err_t
pseries_apply_update (const auth_data_t *auth_data, uint8_t **new_esl_data,
                      size_t *new_esl_data_size, timestamp_t *new_time,
                      sv_flag_t *verified_flag);
/*
 * Given a variable update from a EDK2 EFI_VARIABLE_AUTHENTICATION_2 format
 * message, determine if it is validly signed.
 */
sv_err_t
verify_signature (const auth_data_t *auth_data, const timestamp_t *timestamp,
                  const uint8_t *cert_data, const size_t cert_data_size,
                  const uint8_t *esl_data, const size_t esl_data_size,
                  sv_flag_t *verified_flag);
#endif

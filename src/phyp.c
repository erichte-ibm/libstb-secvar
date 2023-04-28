/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#include "phyp.h"
#include "string.h"
#include "secvar/pseries.h"

static uint64_t phyp_trace_val = 0;

/*
 * Apply an update based on phyp rules.
 *
 * @label/@label_size: variable name
 * @current_data/@current_data_size: current var contents, or NULL/0
 * @update_data: message data
 * @update_data_size: message data length
 * @allow_unauthenticated_pk_update: allow an unauthenticated PK update?
 * @append_update: is this an append?
 * @pk_data/@pk_data_size: the current contents of the PK variable, or NULL/0
 * @kek_data/@kek_data_size: contents of KEK variable or NULL/0
 * @new_data/@new_data_size: out
 * @log_data: out - single uint64_t of trace data
 *
 * If new_data_size is 0, new_data will be NULL. This represents variable deletion.
 * return code: SUCCESS if the update was valid, otherwise an error code.
 *
 * Lifetime: new_data is a fresh allocation if rc = SUCCESS. Caller must free with libstb_free().
 */

int
update_var_from_auth (const uint8_t *label, size_t label_size, const uint8_t *update_data,
                      size_t update_data_size, const uint8_t *current_data,
                      size_t current_data_size, bool allow_unauthenticated_pk_update,
                      bool append_update, const uint8_t *pk_data, size_t pk_data_size,
                      const uint8_t *kek_data, size_t kek_data_size,
                      uint8_t **new_data, size_t *new_data_size, uint64_t *log_data)
{
  sv_err_t rc;
  phyp_trace_val = 0;
  update_req_t update_req = { 0 };

  /* variable update request message */
  update_req.allow_unauthenticated = allow_unauthenticated_pk_update;
  update_req.append_update = append_update;
  update_req.label = label;
  update_req.label_size = label_size;
  update_req.update_data = update_data;
  update_req.update_data_size = update_data_size;
  update_req.current_data = current_data;
  update_req.current_data_size = current_data_size;

  /* authentication certificate database */
  update_req.auth_db.pk = pk_data;
  update_req.auth_db.pk_size = pk_data_size;
  update_req.auth_db.kek = kek_data;
  update_req.auth_db.kek_size = kek_data_size;

  rc = pseries_update_variable (&update_req, new_data, new_data_size);
  *log_data = phyp_trace_val;

  return rc;
}

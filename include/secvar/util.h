/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#ifndef __LIBSTB_SECVAR_UTIL_H
#define __LIBSTB_SECVAR_UTIL_H

#include "config.h"
#include <stdbool.h>
#include <string.h>
#include <external/edk2/common.h>

static inline bool
uuid_equals (const uuid_t *a, const uuid_t *b)
{
  return (memcmp (a, b, UUID_SIZE) == 0);
}

static inline size_t
wide_strlen (const uint16_t *a)
{
  size_t i = 0;

  while (a[i])
    i++;

  return i;
}

static inline bool
wide_str_equals (const uint16_t *a, const uint16_t *b)
{
  size_t alen, blen;
  alen = wide_strlen (a);
  blen = wide_strlen (b);

  return (alen == blen && memcmp (a, b, alen * 2) == 0);
}

#endif

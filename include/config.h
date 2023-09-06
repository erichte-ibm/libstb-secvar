/* 
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#ifndef __LIBSTB_SECVAR_CONFIG_H
#define __LIBSTB_SECVAR_CONFIG_H

/*
 * This is the libstb-secvar config file. You will need to
 *   update this to your deployment platform (e.g. local test,
 * qemu, other product.)
 *
 * This version is for phyp.
 *
 * You must provide the following things:
 *  - endian conversion functions in the style of endian.h
 *  - definitions (either #define or static inline functions) for libstb_zalloc
 *    and libstb_free
 *
 * Optionally, you may define your crypto library here too.
 */

#if defined(__BYTE_ORDER__)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HAVE_LITTLE_ENDIAN 1
#else
#define HAVE_BIG_ENDIAN 1
#endif
#else
#error __BYTE_ORDER__ is undefined, edit config.h
#endif

#include <ccan/endian/endian.h>
#include <stdlib.h>
#include <openssl/crypto.h>

static inline void *
libstb_zalloc (size_t size)
{
  return OPENSSL_zalloc (size);
}

static inline void
libstb_free (void *ptr)
{
  OPENSSL_free (ptr);
}

#endif

/*
 * SPDX-License-Identifier:  BSD-2-Clause
 * Copyright 2023 IBM Corp.
 */
#ifndef __LIBSTB_SECVAR_LOG_H
#define __LIBSTB_SECVAR_LOG_H

#define PR_EMERG 0
#define PR_ALERT 1
#define PR_CRIT 2
#define PR_ERR 3
#define PR_WARNING 4
#define PR_NOTICE 5
#define PR_PRINTF PR_NOTICE
#define PR_INFO 6
#define PR_DEBUG 7
#define PR_TRACE 8
#define PR_INSANE 9
#define MAXLEVEL PR_INSANE

extern int libstb_log_level;

#define prlog(l, ...)                                             \
  do                                                              \
    {                                                             \
      if (l <= libstb_log_level)                                        \
        fprintf ((l <= PR_ERR) ? stderr : stdout, ##__VA_ARGS__); \
    }                                                             \
  while (0)

#endif

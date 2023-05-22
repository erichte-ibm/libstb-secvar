#ifndef _TEST_UTILS_H_
#define _TEST_UTILS_H_

#include <assert.h>

#define assert_msg(expr, ...) do { if (!(expr)) { fprintf (stderr, ##__VA_ARGS__); assert (expr); } } while (0);

#endif
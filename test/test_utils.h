#ifndef _TEST_UTILS_H_
#define _TEST_UTILS_H_

#include <assert.h>
#include <libstb-secvar-errors.h>

#define _ERROR_ROW(a) [a] = #a
const char *_error_table[] = {
  _ERROR_ROW(SV_SUCCESS),
  _ERROR_ROW(SV_BUF_INSUFFICIENT_DATA),
  _ERROR_ROW(SV_ESL_SIZE_INVALID),
  _ERROR_ROW(SV_ESL_WRONG_TYPE),
  _ERROR_ROW(SV_AUTH_INVALID_FIXED_VALUE),
  _ERROR_ROW(SV_AUTH_SIZE_INVALID),
  _ERROR_ROW(SV_AUTH_UNSUPPORTED_REVISION),
  _ERROR_ROW(SV_OUT_BUF_TOO_SMALL),
  _ERROR_ROW(SV_TOO_MUCH_DATA),
  _ERROR_ROW(SV_TIMESTAMP_IN_PAST),
  _ERROR_ROW(SV_ALLOCATION_FAILED),
  _ERROR_ROW(SV_PKCS7_PARSE_ERROR),
  _ERROR_ROW(SV_PKCS7_ERROR),
  _ERROR_ROW(SV_UNEXPECTED_PKCS7_ALGO),
  _ERROR_ROW(SV_X509_PARSE_ERROR),
  _ERROR_ROW(SV_X509_ERROR),
  _ERROR_ROW(SV_UNEXPECTED_CERT_ALGO),
  _ERROR_ROW(SV_UNEXPECTED_CERT_SIZE),
  _ERROR_ROW(SV_UNEXPECTED_CRYPTO_ERROR),
  _ERROR_ROW(SV_CRYPTO_USAGE_BUG),
  _ERROR_ROW(SV_FAILED_TO_VERIFY_SIGNATURE),
  _ERROR_ROW(SV_LABEL_IS_NOT_WIDE_CHARACTERS),
  _ERROR_ROW(SV_UNPACK_ERROR),
  _ERROR_ROW(SV_UNPACK_VERSION_ERROR),
  _ERROR_ROW(SV_CANNOT_APPEND_TO_PK),
  _ERROR_ROW(SV_DELETE_EVERYTHING),
  _ERROR_ROW(SV_INVALID_PK_UPDATE),
  _ERROR_ROW(SV_INVALID_KEK_UPDATE),
};

#define code_to_string(code) (_error_table[code])

// Print an error message before throwing an assert
#define assert_msg(expr, ...) do { if (!(expr)) { fprintf (stderr, ##__VA_ARGS__); assert (expr); } } while (0);

// Compare a return code with an expected value. Should use the enum from libstb-secvar-error.h
//  Will print out the expected error as a string against the received error as a string
#define assert_error(rc, code) do { if (rc != code) { fprintf (stderr, "Expected return code %d (%s), got %d (%s)\n", rc, code_to_string(rc), code, code_to_string(code)); assert(rc == code); } } while (0);

// Helper for the above that assumes the variable named "rc"
#define assert_rc(code) assert_error(rc,code)

#endif
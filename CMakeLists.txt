# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2023 IBM Corp.

cmake_minimum_required( VERSION 3.12 )
project( libstb-secvar C )

add_library ( stb-secvar-openssl STATIC )

target_sources ( stb-secvar-openssl PRIVATE
  src/phyp.c
  src/authentication_2.c
  src/crypto_openssl.c
  src/crypto_util.c
  src/esl.c
  src/pseries.c
  src/update.c
)

target_include_directories ( stb-secvar-openssl AFTER PRIVATE
  ./
  include/
  include/secvar/
  external/endian/
  external/edk2/
)

target_compile_definitions ( stb-secvar-openssl PRIVATE
  SECVAR_CRYPTO_WRITE_FUNC
)

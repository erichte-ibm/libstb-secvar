# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2022-2023 IBM Corp.

CC = gcc
_CFLAGS = -Wall -Werror -MMD -ggdb3 -fPIC
CFLAGS =
LDFLAGS =

SRC_DIR = ../src
BIN_DIR =./bin
LIB_DIR =../lib

INCLUDE = -I../include -I../

TEST_SRCS = test_esl.c \
            test_auth2.c \
            test_update.c \
            test_pseries.c \
            test_phyp.c

_LDFLAGS = $(LDFLAGS) -lcrypto
_CFLAGS += $(CFLAGS) $(INCLUDE)

BINS = $(patsubst %.c,$(BIN_DIR)/%,$(TEST_SRCS))

all: $(BINS)
check: $(patsubst test_%.c,%-check,$(TEST_SRCS))

%-check: $(BIN_DIR)/test_%
	@$<

$(BIN_DIR)/test_%: test_%.c $(LIB_DIR)/libstb-secvar-openssl.a
	@mkdir -p $(BIN_DIR)
	$(CC) -o $@ $^ $(_LDFLAGS) $(_CFLAGS)

cppcheck:
	cppcheck --enable=all --suppress=missingIncludeSystem --force       \
	         -D__BYTE_ORDER__=__LITTLE_ENDIAN__ $(TEST_SRCS) $(INCLUDE) \
			 --error-exitcode=1 -q

cppcheck-be:
	cppcheck --enable=all --suppress=missingIncludeSystem --force    \
	         -D__BYTE_ORDER__=__BIG_ENDIAN__ $(TEST_SRCS) $(INCLUDE) \
			 --error-exitcode=1 -q

clean:
	rm -rf $(BIN_DIR)

.PHONY: all check cppcheck cppecheck-be clean

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

_LDFLAGS = $(LDFLAGS)
_CFLAGS += $(CFLAGS) $(INCLUDE)

#By default, build with openssl as crypto library
CRYPTO_LIB = openssl
ifeq ($(CRYPTO_LIB), openssl)
  _LDFLAGS += -lcrypto  
  _CFLAGS += -DSECVAR_CRYPTO_OPENSSL
endif

BINS = $(patsubst %.c,$(BIN_DIR)/%,$(TEST_SRCS))

all: $(BINS)
check: $(patsubst test_%.c,%-check,$(TEST_SRCS))
memcheck: $(patsubst test_%.c,%-memcheck,$(TEST_SRCS))
coverage: $(patsubst test_%.c,%-coverage,$(TEST_SRCS))

%-check: $(BIN_DIR)/test_%
	@$<

%-memcheck: $(BIN_DIR)/test_%
	@valgrind --leak-check=full --error-exitcode=1 -q $<

%-coverage: $(BIN_DIR)/test_gcov_%
	@$<

.PRECIOUS: $(BIN_DIR)/test_%
$(BIN_DIR)/test_%: test_%.c $(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).a
	@mkdir -p $(BIN_DIR)
	$(CC) -o $@ $^ $(_LDFLAGS) $(_CFLAGS)

.PRECIOUS: $(BIN_DIR)/test_gcov_%
$(BIN_DIR)/test_gcov_%: test_%.c $(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).gcov.a
	@mkdir -p $(BIN_DIR)
	$(CC) -o $@ $^ $(_LDFLAGS) -Wall -Werror -g -O0 --coverage $(INCLUDE)

clean:
	rm -rf $(BIN_DIR)

.PHONY: all check cppcheck cppecheck-be clean coverage

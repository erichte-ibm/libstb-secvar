# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2022-2023 IBM Corp.

CC = gcc
_CFLAGS = -Wall -Werror -MMD -ggdb3 -fPIC
CFLAGS =
LDFLAGS =

SRC_DIR = ../src
BIN_DIR =./bin
LIB_DIR =../lib

STATIC_LIB = 0

INCLUDE = -I../include -I../

TEST_SRCS = ./test_esl.c \
            ./test_auth2.c \
            ./test_update.c \
            ./test_pseries.c \
            ./test_phyp.c

_LDFLAGS = $(LDFLAGS) -lcrypto -lstb-secvar-openssl -L$(LIB_DIR)
_CFLAGS += $(CFLAGS) $(INCLUDE)

TEST_OBJ = $(TEST_SRCS:.c=.o)

all: dirmake test_esl test_auth2 test_update test_pseries test_phyp

ifeq ($(strip $(STATIC_LIB)), 1)
  ifeq ($(wildcard $(LIB_DIR)/*.a),)
	  @$(MAKE) -C ../ STATIC_LIB=$(STATIC_LIB)
  endif
else
  ifeq ($(wildcard $(LIB_DIR)/*.so),)
	  @$(MAKE) -C ../ STATIC_LIB=$(STATIC_LIB)
  endif
endif
	@echo "libstb-secvar test Build successful!"

dirmake:
	@mkdir -p $(BIN_DIR)

check: all
ifeq ($(strip $(STATIC_LIB)), 1)
	@$(BIN_DIR)/test_esl
	@$(BIN_DIR)/test_auth2
	@$(BIN_DIR)/test_update
	@$(BIN_DIR)/test_pseries
	@$(BIN_DIR)/test_phyp
else
	@LD_LIBRARY_PATH=$(LIB_DIR) $(BIN_DIR)/test_esl
	@LD_LIBRARY_PATH=$(LIB_DIR) $(BIN_DIR)/test_auth2
	@LD_LIBRARY_PATH=$(LIB_DIR) $(BIN_DIR)/test_update
	@LD_LIBRARY_PATH=$(LIB_DIR) $(BIN_DIR)/test_pseries
	@LD_LIBRARY_PATH=$(LIB_DIR) $(BIN_DIR)/test_phyp
endif

cppcheck:
	cppcheck --enable=all --suppress=missingIncludeSystem --force \
	         -D__BYTE_ORDER__=__LITTLE_ENDIAN__ $(TEST_SRCS) $(INCLUDE)

cppcheck-be:
	cppcheck --enable=all --suppress=missingIncludeSystem --force \
	         -D__BYTE_ORDER__=__BIG_ENDIAN__ $(TEST_SRCS) $(INCLUDE)

test_esl: test_esl.o
	$(CC) test_esl.o $(_LDFLAGS) -o $(BIN_DIR)/$@

test_auth2: test_auth2.o
	$(CC) test_auth2.o $(_LDFLAGS) -o $(BIN_DIR)/$@

test_update: test_update.o
	$(CC) test_update.o $(_LDFLAGS) -o $(BIN_DIR)/$@

test_pseries: test_pseries.o
	$(CC) test_pseries.o $(_LDFLAGS) -o $(BIN_DIR)/$@

test_phyp: test_phyp.o
	$(CC) test_phyp.o $(_LDFLAGS) -o $(BIN_DIR)/$@

%.o: %.c
	$(CC) $(_CFLAGS) $< -o $@ -c

clean:
	find ./ -name "*.[od]" -delete
	rm -rf $(BIN_DIR)

.PHONY: all check cppcheck cppecheck-be clean

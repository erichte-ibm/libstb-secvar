# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2023 IBM Corp.

CC = gcc
AR = ar
LD = gcc
_CFLAGS = -Wall -Werror -MMD -ggdb3 -fPIC
CFLAGS =
LDFLAGS =

SRC_DIR = ./src
OBJ_DIR = ./obj
LIB_DIR = ./lib
TEST_DIR = ./test

INCLUDE = -I./include -I./

DEBUG ?= 0
ifeq ($(strip $(DEBUG)), 1)
  _CFLAGS += -g
else
  _LDFLAGS += -s
endif

# Handle coverage generator preference, only supports lcov/gcovr via the Makefile
#  consider using the `make coverage` target and manually running your if not supported
ifeq ($(strip $(PREFER_LCOV)), 1)
  COVERER = lcov
else ifeq ($(strip $(PREFER_GCOVR)), 1)
  COVERER = gcovr
else
  # Default to preferring gcovr if it exists, fallback to lcov if not
  ifneq ($(strip $(shell which gcovr)),)
    COVERER = gcovr
  else ifneq ($(strip $(shell which lcov)),)
    COVERER = lcov
  else
  endif
endif

#use CRYPTO_READ_ONLY for smaller executable but limited functionality
#removes all write functions (secvarctl generate, pem_to_der etc.)
CRYPTO_READ_ONLY = 1
ifeq ($(strip $(CRYPTO_READ_ONLY)), 0)
  _CFLAGS += -DSECVAR_CRYPTO_WRITE_FUNC
endif

SRCS = esl.c \
       authentication_2.c \
       update.c \
       pseries.c \
       crypto_util.c \
       log.c \
       phyp.c

#By default, build with openssl as crypto library
CRYPTO_LIB = openssl
ifeq ($(CRYPTO_LIB), openssl)
  SRCS += crypto_openssl.c
  CRYPTO_ARG = OPENSSL=1
  _CFLAGS += -DSECVAR_CRYPTO_OPENSSL
endif

SRCS := $(addprefix $(SRC_DIR)/,$(SRCS))

OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
COV_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.gcov.o,$(SRCS))
_CFLAGS += $(CFLAGS) $(INCLUDE)
_LDFLAGS += $(LDFLAGS)

all: $(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).a $(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).so

-include $(OBJS:.o=.d)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(_CFLAGS) $< -o $@ -c

# Coverage objects
$(OBJ_DIR)/%.gcov.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) -Wall -Werror -g -O0 --coverage -DNO_PRLOG $(INCLUDE) $< -o $@ -c

$(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).a: $(OBJS)
	@mkdir -p $(LIB_DIR)
	$(AR) -rcs $@ $^ $(_LDFLAGS)

$(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).gcov.a: $(COV_OBJS)
	@mkdir -p $(LIB_DIR)
	$(AR) -rcs $@ $^ $(_LDFLAGS)

$(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).so: $(OBJS)
	@mkdir -p $(LIB_DIR)
	$(LD) $(_LDFLAGS) -shared $^ -o $@

tests: $(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).a
	@$(MAKE) -C $(TEST_DIR) $(CRYPTO_ARG)

check: $(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).a
	@$(MAKE) -C $(TEST_DIR) $(CRYPTO_ARG) check

memcheck: $(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).a
	@$(MAKE) -C $(TEST_DIR) memcheck

coverage: $(LIB_DIR)/libstb-secvar-$(CRYPTO_LIB).gcov.a
	@$(MAKE) -C $(TEST_DIR) coverage

coverage-report: coverage
ifeq ($(COVERER),)
	$(error Neither lcov nor gcovr appear to be installed, please install one of them to use this target)
endif
ifeq ($(PERSIST_REPORT),)
	rm -rf report
endif
	@mkdir -p report

ifeq ($(COVERER),lcov)
	@echo "Using lcov to generate report"
	@lcov --no-external --capture --directory . --output-file report/test.info
	@genhtml report/test.info --legend --output-directory=report
else ifeq ($(COVERER),gcovr)
	@echo "Using gcovr to generate report"
	@gcovr --html-details report/index.html --delete
endif

TEST_SRCS = $(wildcard test/*.c)
# variableScope: avoid reducing variable scope to maintain C compatibility
# missingInclude: TODO: ideally rework all includes to make this unnecessary
# unusedFunction: not all functions provided in the library might be used
#  TODO: should be removed when test coverage improves
CPPCHECK_ARGS = --enable=all --force            \
                --suppress=variableScope        \
                --suppress=missingInclude       \
                --suppress=unusedFunction       \
                --error-exitcode=1 -q
cppcheck:
	cppcheck $(CPPCHECK_ARGS)                    \
             -D__BYTE_ORDER__=__LITTLE_ENDIAN__  \
             $(INCLUDE) $(SRCS) $(TEST_SRCS)

cppcheck-be:
	cppcheck $(CPPCHECK_ARGS)                \
             -D__BYTE_ORDER__=__BIG_ENDIAN__ \
             $(INCLUDE) $(SRCS) $(TEST_SRCS)

clean:
	@$(MAKE) -C $(TEST_DIR) clean
	rm -rf $(OBJ_DIR) $(LIB_DIR)
	rm -rf report/

.PHONY: all check cppcheck cppcheck-be clean tests coverage coverage-report

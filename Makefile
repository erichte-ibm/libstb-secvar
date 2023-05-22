# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2023 IBM Corp.

CC = gcc
AR = ar
LD = gcc
_CFLAGS = -Wall -Werror -MMD -ggdb3 -fPIC
CFLAGS =
LDFLAGS =

SRC_DIR = ./src
LIB_DIR = ./lib
TEST_DIR = ./test

INCLUDE = -I./include -I./

DEBUG ?= 0
ifeq ($(strip $(DEBUG)), 1)
  _CFLAGS += -g
else
  _LDFLAGS += -s
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
       phyp.c

SRCS += crypto_openssl.c

SRCS := $(addprefix $(SRC_DIR)/,$(SRCS))

OBJS = $(SRCS:.c=.o)
_CFLAGS += $(CFLAGS) $(INCLUDE)
_LDFLAGS += $(LDFLAGS)

all: $(LIB_DIR)/libstb-secvar-openssl.a $(LIB_DIR)/libstb-secvar-openssl.so

-include $(OBJS:.o=.d)

%.o: %.c
	$(CC) $(_CFLAGS) $< -o $@ -c

$(LIB_DIR)/libstb-secvar-openssl.a: $(OBJS)
	@mkdir -p $(LIB_DIR)
	$(AR) -rcs $@ $^ $(_LDFLAGS)

$(LIB_DIR)/libstb-secvar-openssl.so: $(OBJS)
	@mkdir -p $(LIB_DIR)
	$(LD) $(_LDFLAGS) -shared $^ -o $@

check: $(LIB_DIR)/libstb-secvar-openssl.so test
	@$(MAKE) -C $(TEST_DIR) check

cppcheck:
	cppcheck --enable=all --suppress=missingIncludeSystem --force \
	         -D__BYTE_ORDER__=__LITTLE_ENDIAN__ $(SRCS) $(INCLUDE)
	@$(MAKE) -C $(TEST_DIR) cppcheck

cppcheck-be:
	cppcheck --enable=all --suppress=missingIncludeSystem --force \
	         -D__BYTE_ORDER__=__BIG_ENDIAN__ $(SRCS) $(INCLUDE)
	@$(MAKE) -C $(TEST_DIR) cppcheck-be

clean:
	@$(MAKE) -C $(TEST_DIR) clean
	find $(SRC_DIR) -name "*.[od]" -delete
	rm -rf $(LIB_DIR)

.PHONY: all check cppcheck cppcheck-be clean

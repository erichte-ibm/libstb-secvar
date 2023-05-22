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


SRCS = $(SRC_DIR)/esl.c \
       $(SRC_DIR)/authentication_2.c \
       $(SRC_DIR)/update.c \
       $(SRC_DIR)/pseries.c \
       $(SRC_DIR)/phyp.c

OPENSSL_SRCS = $(SRCS) \
               $(SRC_DIR)/crypto_openssl.c \
               $(SRC_DIR)/crypto_util.c

OPENSSL_OBJS = $(SRCS:.c=.openssl.o) $(OPENSSL_SRCS:.c=.openssl.o)
_CFLAGS += $(CFLAGS) $(INCLUDE)
_LDFLAGS += $(LDFLAGS)

all: $(LIB_DIR)/libstb-secvar-openssl.a $(LIB_DIR)/libstb-secvar-openssl.so

-include $(OPENSSL_OBJS:.o=.d)

%.o: %.c
	$(CC) $(_CFLAGS) $< -o $@ -c
%.openssl.o: %.c
	$(CC) $(_CFLAGS) $< -o $@ -c

$(LIB_DIR)/libstb-secvar-openssl.a: $(OPENSSL_OBJS)
	@mkdir -p $(LIB_DIR)
	$(AR) -rcs $@ $^ $(_LDFLAGS)

$(LIB_DIR)/libstb-secvar-openssl.so: $(OPENSSL_OBJS)
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

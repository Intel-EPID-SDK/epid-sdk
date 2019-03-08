#!/usr/bin/make -f

API_INCLUDE_DIR = ./include
SRC_INCLUDE_DIR = ./sources/include
LIB_INSTALL_DIR = $(epidinstalldir)/lib/posix-$(ARCH)/

PCP_INCLUDE_DIR = ./sources/ippcp
PCP_SRC = $(wildcard ./sources/ippcp/*.c)
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcparcfour*.c), $(PCP_SRC))
PCP_SRC := $(filter-out ./sources/ippcp/pcpmain.c, $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/*sm2.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpsha1ca.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpaes*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpdes*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpdlp*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcphmac*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpmd5*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpng*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpprime*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcprij*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcprsa*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpsm3*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcpsms4*.c), $(PCP_SRC))
PCP_SRC := $(filter-out $(wildcard ./sources/ippcp/pcptdes*.c), $(PCP_SRC))
PCP_SRC := $(filter-out ./sources/ippcp/pcpmont_expbinbnu_sscm.c, $(PCP_SRC))
PCP_SRC := $(filter-out ./sources/ippcp/pcpmont_expwinbnu.c, $(PCP_SRC))
PCP_SRC := $(filter-out ./sources/ippcp/pcpmont_expwinbnu_sscm.c, $(PCP_SRC))

PCP_OBJ = $(PCP_SRC:.c=.o)
PCP_LIB = ./sources/ippcp/libippcp.a

ifeq ($(ARCH), x86)
	CFLAGS += -D_ARCH_IA32
else
	CFLAGS += -D_ARCH_EM64T
endif
CFLAGS += -D_IPP_DEBUG
CFLAGS += -D_IPP_DEBUG
CFLAGS += -D_IPP_C99
CFLAGS += -D_IPP_v50_
CFLAGS += -D_PX
CFLAGS += -D_ABL_
CFLAGS += -D_DISABLE_ECP_SM2_
CFLAGS += -D_DISABLE_ALG_SHA224_
CFLAGS += -D_DISABLE_ALG_SHA512_224_
CFLAGS += -D_DISABLE_ALG_MD5_
CFLAGS += -D_DISABLE_ALG_SM3_

$(PCP_OBJ): %.o: %.c
	$(CC) $(CFLAGS) $(IPP_FLAGS) -I$(API_INCLUDE_DIR) -I$(SRC_INCLUDE_DIR) -I$(PCP_INCLUDE_DIR) -c -o $@ $<

$(PCP_LIB): $(PCP_OBJ)
	$(AR) rc $@ $^
	$(RANLIB) $@

build: all

all: $(PCP_LIB)

install:
	mkdir -p '$(LIB_INSTALL_DIR)'
	cp $(PCP_LIB) '$(LIB_INSTALL_DIR)'

clean:
	rm -f $(PCP_OBJ) $(PCP_LIB)

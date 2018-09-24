#!/usr/bin/make -f

#define variables
IPP_API_INCLUDE_DIR = ../ext/ipp/include
EXAMPLE_INSTALL_DIR = $(epidinstalldir)/bin
DATA_INSTALL_DIR = $(epidinstalldir)/data
NON_SPLIT_DATA_INSTALL_DIR = $(DATA_INSTALL_DIR)/non_split
SPLIT_DATA_INSTALL_DIR = $(DATA_INSTALL_DIR)/split

SIGNMSG_INCLUDE_DIR = ./signmsg
SIGNMSG_SRC = $(wildcard ./signmsg/src/*.c)
SIGNMSG_OBJ = $(SIGNMSG_SRC:.c=.o)
SIGNMSG_EXE = ./signmsg/src/signmsg$(EXE_EXTENSION)

VERIFYSIG_INCLUDE_DIR = ./verifysig
VERIFYSIG_SRC = $(wildcard ./verifysig/src/*.c)
VERIFYSIG_OBJ = $(VERIFYSIG_SRC:.c=.o)
VERIFYSIG_EXE = ./verifysig/src/verifysig$(EXE_EXTENSION)


LIB_UTIL_DIR = ./util/src
LIB_ARGTABLE_DIR = ../ext/argtable3
LIB_IPPCP_DIR = ../ext/ipp/sources/ippcp/src
LIB_MEMBER_DIR = ../epid/member
LIB_VERIFIER_DIR = ../epid/verifier
LIB_COMMON_DIR = ../epid/common

#set linker flags
LDFLAGS += -L$(LIB_UTIL_DIR) \
	-L$(LIB_ARGTABLE_DIR) \
	-L$(LIB_IPPCP_DIR) \
	-L$(LIB_COMMON_DIR) \
	-lcommon \
	-lippcp -lutil -largtable3

ifneq ($(TSS_PATH),)
	LDFLAGS += -Wl,--rpath,'$$ORIGIN/../lib/posix-$(ARCH)' # runtime path to tss
	LDFLAGS += -L$(TSS_PATH) -ltss -lcrypto
endif

ifeq ($(TINY),yes)
	LDFLAGS += -L$(LIB_MEMBER_DIR) -lmath -ltiny_stdlib
endif

$(VERIFYSIG_EXE): $(VERIFYSIG_OBJ)
	$(CC) -o $@ $^ -L$(LIB_VERIFIER_DIR) -lverifier $(LDFLAGS)

$(VERIFYSIG_OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(LIB_UTIL_DIR)/../.. \
			-I$(LIB_ARGTABLE_DIR) \
			-I$(LIB_VERIFIER_DIR)/../.. \
			-I$(VERIFYSIG_INCLUDE_DIR) \
			-I$(IPP_API_INCLUDE_DIR) -c $^

ifneq ($(SHARED_MODE),yes)
    MEMBER_LIBS_TO_LINK = -lmember
else
    MEMBER_LIBS_TO_LINK = $(LIB_MEMBER_DIR)/libmember.so
endif
$(SIGNMSG_EXE): $(SIGNMSG_OBJ)
	$(CC) -o $@ $^ -L$(LIB_MEMBER_DIR) $(MEMBER_LIBS_TO_LINK) $(LDFLAGS)

$(SIGNMSG_OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(LIB_UTIL_DIR)/../.. \
			-I$(LIB_ARGTABLE_DIR) \
			-I$(LIB_MEMBER_DIR)/../.. \
			-I$(SIGNMSG_INCLUDE_DIR) \
			-I$(IPP_API_INCLUDE_DIR) -c $^

#target part
build: all install

all: $(VERIFYSIG_EXE) $(SIGNMSG_EXE)

install:
	mkdir -p '$(DATA_INSTALL_DIR)'
	find data/. \( -iname '*.bin' -o -iname '*.dat' -o \
		-iname '*.md' \) -a ! -iname '*-priv.dat' -print0 \
		| xargs -0 cp --parents -t '$(DATA_INSTALL_DIR)'
	mv '$(DATA_INSTALL_DIR)/data' '$(NON_SPLIT_DATA_INSTALL_DIR)'
	find split_data/. \( -iname '*.bin' -o -iname '*.dat' -o \
		-iname '*.md' \) -a ! -iname '*-priv.dat' -print0 \
		| xargs -0 cp --parents -t '$(DATA_INSTALL_DIR)'
	mv '$(DATA_INSTALL_DIR)/split_data' '$(SPLIT_DATA_INSTALL_DIR)'
	mkdir -p '$(EXAMPLE_INSTALL_DIR)'
	cp $(VERIFYSIG_EXE) $(SIGNMSG_EXE) '$(EXAMPLE_INSTALL_DIR)'

clean:
	rm -f $(VERIFYSIG_OBJ) \
		$(VERIFYSIG_EXE) \
		$(SIGNMSG_OBJ) \
		$(SIGNMSG_EXE)

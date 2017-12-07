#!/usr/bin/make -f

#define variables
TOOLS_INSTALL_DIR = $(epidinstalldir)/tools

EXTRACTGRPS_INCLUDE_DIR = ./extractgrps
EXTRACTGRPS_SRC = $(wildcard ./extractgrps/src/*.c)
EXTRACTGRPS_OBJ = $(EXTRACTGRPS_SRC:.c=.o)
EXTRACTGRPS_EXE = ./extractgrps/src/extractgrps$(EXE_EXTENSION)

EXTRACTKEYS_INCLUDE_DIR = ./extractkeys
EXTRACTKEYS_SRC = $(wildcard ./extractkeys/src/*.c)
EXTRACTKEYS_OBJ = $(EXTRACTKEYS_SRC:.c=.o)
EXTRACTKEYS_EXE = ./extractkeys/src/extractkeys$(EXE_EXTENSION)

REVOKEGRP_INCLUDE_DIR = ./revokegrp
REVOKEGRP_SRC = $(wildcard ./revokegrp/src/*.c)
REVOKEGRP_OBJ = $(REVOKEGRP_SRC:.c=.o)
REVOKEGRP_EXE = ./revokegrp/src/revokegrp$(EXE_EXTENSION)

REVOKEKEY_INCLUDE_DIR = ./revokekey
REVOKEKEY_SRC = $(wildcard ./revokekey/src/*.c)
REVOKEKEY_OBJ = $(REVOKEKEY_SRC:.c=.o)
REVOKEKEY_EXE = ./revokekey/src/revokekey$(EXE_EXTENSION)

REVOKESIG_INCLUDE_DIR = ./revokesig
REVOKESIG_SRC = $(wildcard ./revokesig/src/*.c)
REVOKESIG_OBJ = $(REVOKESIG_SRC:.c=.o)
REVOKESIG_EXE = ./revokesig/src/revokesig$(EXE_EXTENSION)

EPID_SDK_ROOT_DIR = ..
EXAMPLE_DIR = $(EPID_SDK_ROOT_DIR)/example
LIB_ARGTABLE_DIR = $(EPID_SDK_ROOT_DIR)/ext/argtable3
LIB_UTIL_DIR = $(EPID_SDK_ROOT_DIR)/example/util/src
LIB_IPPCP_DIR = $(EPID_SDK_ROOT_DIR)/ext/ipp/sources/ippcp/src
LIB_MEMBER_DIR = $(EPID_SDK_ROOT_DIR)/epid/member
LIB_COMMON_DIR = $(EPID_SDK_ROOT_DIR)/epid/common

#set linker flags
LDFLAGS += -L$(LIB_UTIL_DIR) \
	-L$(LIB_ARGTABLE_DIR) \
	-L$(LIB_IPPCP_DIR) \
	-L$(LIB_COMMON_DIR) \
	-lcommon \
	-lippcp -lutil -largtable3

$(EXTRACTGRPS_EXE): $(EXTRACTGRPS_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(EXTRACTGRPS_OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(EPID_SDK_ROOT_DIR) \
			-I${EXAMPLE_DIR} -I$(EXTRACTGRPS_INCLUDE_DIR) \
			-I${LIB_ARGTABLE_DIR} \
			-c $^

$(EXTRACTKEYS_EXE): $(EXTRACTKEYS_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(EXTRACTKEYS_OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(EPID_SDK_ROOT_DIR) \
			-I${EXAMPLE_DIR} -I$(EXTRACTKEYS_INCLUDE_DIR) \
			-I${LIB_ARGTABLE_DIR} \
			-c $^

$(REVOKEGRP_EXE): $(REVOKEGRP_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(REVOKEGRP_OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(EPID_SDK_ROOT_DIR) \
			-I${EXAMPLE_DIR} -I$(REVOKEGRP_INCLUDE_DIR) \
			-I${LIB_ARGTABLE_DIR} \
			-c $^

MEMBER_LIBS = -lmember
ifneq ($(TINY),)
    MEMBER_LIBS += -lmath -ltiny_stdlib
endif
$(REVOKEKEY_EXE): $(REVOKEKEY_OBJ)
	$(CC) -o $@ $^ -L$(LIB_MEMBER_DIR) $(MEMBER_LIBS) $(LDFLAGS)

$(REVOKEKEY_OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(EPID_SDK_ROOT_DIR) \
			-I$(LIB_MEMBER_DIR)/../.. \
			-I${EXAMPLE_DIR} -I$(REVOKEKEY_INCLUDE_DIR) \
			-I${LIB_ARGTABLE_DIR} \
			-c $^

$(REVOKESIG_EXE): $(REVOKESIG_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(REVOKESIG_OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(EPID_SDK_ROOT_DIR) \
			-I${EXAMPLE_DIR} -I$(REVOKESIG_INCLUDE_DIR) \
			-I${LIB_ARGTABLE_DIR} \
			-c $^

#target part
build: all install

all: $(EXTRACTGRPS_EXE) $(EXTRACTKEYS_EXE) $(REVOKEGRP_EXE) $(REVOKEKEY_EXE) $(REVOKESIG_EXE)

install:
	mkdir -p '$(TOOLS_INSTALL_DIR)'
	cp $(EXTRACTGRPS_EXE) $(EXTRACTKEYS_EXE) $(REVOKEGRP_EXE) $(REVOKEKEY_EXE) $(REVOKESIG_EXE) \
		'$(TOOLS_INSTALL_DIR)'

clean:
	rm -f $(EXTRACTGRPS_EXE) $(EXTRACTKEYS_EXE) $(REVOKEGRP_EXE) $(REVOKEKEY_EXE) $(REVOKESIG_EXE) \
	$(EXTRACTGRPS_OBJ) $(EXTRACTKEYS_OBJ) $(REVOKEGRP_OBJ) $(REVOKEKEY_OBJ) $(REVOKESIG_OBJ)

#!/usr/bin/make -f

#define path variables
IPP_SRC_INCLUDE_DIR = ../../ext/ipp/sources/ippcp/src/
IPP_INCLUDE_DIR = ../../ext/ipp/sources/include/
GTEST_INCLUDE_DIR = ../../ext/

LIB_INSTALL_DIR = $(epidinstalldir)/lib/posix-$(ARCH)/
TEST_INSTALL_DIR = $(epidinstalldir)/utest/
HEADERS_INSTALL_DIR :=  $(epidinstalldir)/include/epid/member/

API_HEADERS_INSTALL = $(wildcard ./*.h)

MEMBER_INCLUDE_DIR = ../../
TINY_MEMBER_INCLUDE_DIR = ./tiny/

MEMBER_SRC =  $(wildcard ./split/src/*.c)
TINY_MEMBER_SRC =  $(wildcard ./tiny/src/*.c)
TINY_MEMBER_MATH_SRC =  $(wildcard ./tiny/math/src/*.c)
TINY_STDLIB_MEMBER_SRC =  $(wildcard ./tiny/stdlib/src/*.c)
MEMBER_TPM2_TSS_UTEST_SRC = $(wildcard ./split/tpm2/unittests/*.cc)
TSS_LIB = $(wildcard $(TSS_PATH)/libtss.so*)
ifneq ($(TSS_PATH),)
	MEMBER_TPM2_SRC = $(wildcard ./split/tpm2/ibm_tss/*.c)
	MEMBER_TPM2_UTEST_SRC = $(filter-out $(wildcard ./split/tpm2/unittests/*-simulator-test.cc), \
		$(MEMBER_TPM2_TSS_UTEST_SRC))
	MEMBER_INCLUDE_DIR += -I$(TSS_PATH)
	CFLAGS += -DTPM_TSS
	CXXFLAGS += -DTPM_TSS
else
	MEMBER_TPM2_SRC = $(wildcard ./split/tpm2/builtin/*.c)
	MEMBER_TPM2_UTEST_SRC = $(filter-out $(wildcard ./split/tpm2/unittests/*-tss-test.cc), \
		$(MEMBER_TPM2_TSS_UTEST_SRC))
endif
MEMBER_SRC += $(MEMBER_TPM2_SRC)
MEMBER_STATIC_LIB = ./libmember.a
MEMBER_SHARED_LIB = ./libmember.so
MATH_LIB = ./libmath.a
STDLIB_LIB = ./libtiny_stdlib.a
MEMBER_UTEST_EXE = ./member-utest$(EXE_EXTENSION)
MEMBER_UTEST_SRC = $(wildcard ./split/unittests/*.cc) \
		./split/tpm2/unittests/tpm2_wrapper-testhelper.cc
TINY_MEMBER_UTEST_SRC = $(wildcard ./tiny/unittests/*.cc) \
		$(wildcard ./tiny/unittests/internal/*.cc)
TINY_MEMBER_MATH_UTEST_SRC = $(wildcard ./tiny/math/unittests/*.cc) \
		$(wildcard ./tiny/math/unittests/internal/*.cc)

ifneq ($(SHARED_MODE),yes)
	MEMBER_LIB = $(MEMBER_STATIC_LIB)
else
	MEMBER_LIB = $(MEMBER_SHARED_LIB)
endif

ifeq ($(TINY),yes)
	MEMBER_OBJ = $(TINY_MEMBER_SRC:.c=.o)
	MATH_OBJ = $(TINY_MEMBER_MATH_SRC:.c=.o)
	STDLIB_OBJ = $(TINY_STDLIB_MEMBER_SRC:.c=.o)
	MEMBER_UTEST_OBJ = $(TINY_MEMBER_UTEST_SRC:.cc=.o)
	TINY_MEMBER_MATH_UTEST_OBJ = $(TINY_MEMBER_MATH_UTEST_SRC:.cc=.o)
	MEMBER_INCLUDE_DIR += -I$(TINY_MEMBER_INCLUDE_DIR)
	CFLAGS += -DTINY
	CXXFLAGS += -DTINY
else
	MEMBER_OBJ = $(MEMBER_SRC:.c=.o)
	MEMBER_UTEST_OBJ = $(MEMBER_UTEST_SRC:.cc=.o)
	MEMBER_TPM2_UTEST_OBJ = $(MEMBER_TPM2_UTEST_SRC:.cc=.o)
endif

LIB_MEMBER_DIR = .
LIB_VERIFIER_DIR = ../verifier
LIB_COMMON_TESTHELPER_DIR = ../common-testhelper
LIB_COMMON_DIR = ../common
LIB_IPPCP_DIR = ../../ext/ipp/sources/ippcp/src
ifneq ($(SHARED_MODE),yes)
	MEMBER_LIBS_TO_LINK = -lmember
else
	MEMBER_LIBS_TO_LINK = $(LIB_MEMBER_DIR)/libmember.so
endif
#set flags for linker
LDFLAGS += -L$(GTEST_INCLUDE_DIR)/gtest  -L$(LIB_COMMON_TESTHELPER_DIR)  \
	-L$(LIB_MEMBER_DIR) -L$(LIB_VERIFIER_DIR) -L$(LIB_COMMON_DIR) \
	-L$(LIB_IPPCP_DIR) -lgtest -lcommon-testhelper \
	$(MEMBER_LIBS_TO_LINK) -lverifier -lcommon -lippcp

ifneq ($(TSS_PATH),)
	LDFLAGS += -Wl,--rpath,'$$ORIGIN/../lib/posix-$(ARCH)' # runtime path to tss
	LDFLAGS +=-L$(TSS_PATH) -ltss -lcrypto
endif

ifeq ($(TINY),yes)
  CPPDEFINES := -DNDEBUG
	LDFLAGS += -lmath -ltiny_stdlib
	CFLAGS := -Os -fno-builtin -fno-stack-protector -fomit-frame-pointer \
			-fno-asynchronous-unwind-tables -fdata-sections \
			-ffunction-sections -fvisibility=hidden -Werror \
			-Wall -Wextra
	ifneq ($(OS),Windows_NT)
		CFLAGS += -fPIC
	endif
	ifeq ($(findstring gcc,$(CC)),gcc)
		CFLAGS += -Wno-missing-braces
	else ifeq ($(findstring clang,$(CC)),clang)
		CFLAGS += -Wno-missing-braces -Wno-typedef-redefinition
	endif
	ifeq ($(ARCH), x86)
		CFLAGS += -m32
	endif
endif

ifeq ($(SHARED_MODE),yes)
	#for library
	CFLAGS += -fstack-usage -fdump-tree-cfg-raw -DNDEBUG -DSHARED
	#for tests
	CXXFLAGS += -DSHARED
	LDFLAGS += -Wl,-rpath=.
endif

$(MEMBER_OBJ): %.o: %.c
	$(CC) $(CFLAGS) -I$(IPP_INCLUDE_DIR) -I$(IPP_SRC_INCLUDE_DIR) \
	-I$(MEMBER_INCLUDE_DIR) -c $^ -o $@

$(MEMBER_STATIC_LIB): $(MEMBER_OBJ)
	$(AR) rc $(MEMBER_STATIC_LIB) $(MEMBER_OBJ)
	$(RANLIB) $(MEMBER_STATIC_LIB)

$(MEMBER_SHARED_LIB): $(MEMBER_OBJ)
	$(CC) -o $@ $^ -L$(LIB_MEMBER_DIR) -shared -nodefaultlibs -nostdlib \
		-nostartfiles -s -Xlinker --gc-sections -lmath \
		-ltiny_stdlib -Wl,--no-undefined

$(MEMBER_UTEST_EXE): $(MEMBER_UTEST_OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS)

$(MEMBER_UTEST_OBJ): %.o: %.cc
	$(CXX) -o $@ $(CXXFLAGS) $(GTEST_DEFINES) -I$(MEMBER_INCLUDE_DIR) \
	-I$(GTEST_INCLUDE_DIR) -c $^

ifeq ($(TINY),yes)
    $(MATH_OBJ): %.o: %.c
		$(CC) $(CFLAGS) -I$(MEMBER_INCLUDE_DIR) -c $^ -o $@

    $(STDLIB_OBJ): %.o: %.c
		$(CC) $(CFLAGS) -I$(MEMBER_INCLUDE_DIR) -c $^ -o $@

    $(MATH_LIB): $(MATH_OBJ)
		$(AR) rc $(MATH_LIB) $(MATH_OBJ)
		$(RANLIB) $(MATH_LIB)

    $(STDLIB_LIB): $(STDLIB_OBJ)
		$(AR) rc $(STDLIB_LIB) $(STDLIB_OBJ)
		$(RANLIB) $(STDLIB_LIB)

    TINY_MEMBER_MATH_UTEST_EXE = ./member.math-utest$(EXE_EXTENSION)
    $(TINY_MEMBER_MATH_UTEST_EXE): $(TINY_MEMBER_MATH_UTEST_OBJ)
		$(CXX) -o $@ $^ $(LDFLAGS)

    $(TINY_MEMBER_MATH_UTEST_OBJ): %.o: %.cc
		$(CXX) -o $@ $(CXXFLAGS) $(GTEST_DEFINES) -I$(MEMBER_INCLUDE_DIR) \
		-I$(GTEST_INCLUDE_DIR) -c $^
else
    MEMBER_TPM2_UTEST_EXE = ./member.tpm2-utest$(EXE_EXTENSION)
    $(MEMBER_TPM2_UTEST_EXE): $(MEMBER_TPM2_UTEST_OBJ)
		$(CXX) -o $@ $^ $(LDFLAGS)

    $(MEMBER_TPM2_UTEST_OBJ): %.o: %.cc
		$(CXX) -o $@ $(CXXFLAGS) $(GTEST_DEFINES) -I$(MEMBER_INCLUDE_DIR) \
		-I$(GTEST_INCLUDE_DIR) -c $^
endif
build: all
ifeq ($(TINY),yes)
    LIBS = $(STDLIB_LIB) $(MATH_LIB)
endif
LIBS += $(MEMBER_LIB)
all: $(LIBS)
install:
	mkdir -p '$(LIB_INSTALL_DIR)'
	mkdir -p '$(HEADERS_INSTALL_DIR)'
	cp $(MEMBER_LIB) '$(LIB_INSTALL_DIR)'
ifeq ($(TINY),yes)
	cp $(MATH_LIB) '$(LIB_INSTALL_DIR)'
	cp $(STDLIB_LIB) '$(LIB_INSTALL_DIR)'
endif
	cp $(API_HEADERS_INSTALL) '$(HEADERS_INSTALL_DIR)'
#install tests if they exist
ifneq (,$(wildcard $(MEMBER_UTEST_EXE)))
	mkdir -p '$(TEST_INSTALL_DIR)'
	cp $(MEMBER_UTEST_EXE) '$(TEST_INSTALL_DIR)'
endif
ifneq (,$(wildcard $(TINY_MEMBER_MATH_UTEST_EXE)))
	mkdir -p '$(TEST_INSTALL_DIR)'
	cp $(TINY_MEMBER_MATH_UTEST_EXE) '$(TEST_INSTALL_DIR)'
endif
ifneq (,$(wildcard $(MEMBER_TPM2_UTEST_EXE)))
	mkdir -p '$(TEST_INSTALL_DIR)'
	cp $(MEMBER_TPM2_UTEST_EXE) '$(TEST_INSTALL_DIR)'
endif
#copy TSS libs to lib folder
ifneq ($(TSS_PATH),)
	cp $(wildcard $(TSS_LIB)) '$(LIB_INSTALL_DIR)'
endif

utest: $(MEMBER_UTEST_EXE) $(MEMBER_TPM2_UTEST_EXE) $(TINY_MEMBER_MATH_UTEST_EXE)

run_utest:
	$(MEMBER_UTEST_EXE) $(GTEST_FLAGS)
ifeq ($(TINY),yes)
	$(TINY_MEMBER_MATH_UTEST_EXE) $(GTEST_FLAGS)
else
	$(MEMBER_TPM2_UTEST_EXE) $(GTEST_FLAGS)
endif

check: utest run_utest

clean:
	rm -f $(MEMBER_OBJ) \
		$(MEMBER_LIB) \
		$(MATH_OBJ) \
		$(MATH_LIB) \
		$(STDLIB_OBJ) \
		$(STDLIB_LIB) \
		$(MEMBER_UTEST_OBJ) \
		$(MEMBER_UTEST_EXE) \
		$(MEMBER_TPM2_UTEST_OBJ) \
		$(MEMBER_TPM2_UTEST_EXE) \
		$(TINY_MEMBER_MATH_UTEST_OBJ) \
		$(TINY_MEMBER_MATH_UTEST_EXE) \
		*.xml

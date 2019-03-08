#!/usr/bin/make -f
build: all

GTEST_LIB = libgtest.a

GTEST_DIR = googletest

GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h


GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

# For simplicity and to avoid depending on Google Test's
# implementation details, the dependencies specified below are
# conservative and not optimized.  This is fine as Google Test
# compiles fast and for ordinary users its source rarely changes.
gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) $(GTEST_DEFINES) \
            -I$(GTEST_DIR) -I$(GTEST_DIR)/include \
	    $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

$(GTEST_LIB) : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^
	$(RANLIB) $@

all: $(GTEST_LIB)

install:

clean:
	rm -f gtest-all.o $(GTEST_LIB)

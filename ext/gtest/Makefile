#!/usr/bin/make -f

GTEST_INCLUDE_DIR = ..
GTEST_SRC = $(wildcard ./*.cc)
GTEST_OBJ = $(GTEST_SRC:.cc=.o)

GTEST_LIB = libgtest.a

$(GTEST_OBJ): %.o: %.cc
	$(CXX) -o $@ -c $(CXXFLAGS) $(GTEST_DEFINES) -I$(GTEST_INCLUDE_DIR) $<

$(GTEST_LIB): $(GTEST_OBJ)
	$(AR) rc $@ $^
	$(RANLIB) $@

build: all

all: $(GTEST_LIB)

install:

clean:
	rm -f $(GTEST_OBJ) $(GTEST_LIB)

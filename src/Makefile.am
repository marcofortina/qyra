# Copyright (c) 2024 Marco Fortina
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

# General linking flags
AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(LDFLAGS)

# C++ compilation flags
AM_CXXFLAGS = $(CXXFLAGS) $(DEBUG_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS)

# Objective-C++ compilation flags, using the same as C++
AM_OBJCXXFLAGS = $(AM_CXXFLAGS)

# Preprocessor flags
AM_CPPFLAGS = $(CPPFLAGS) $(DEBUG_CPPFLAGS)

# Flags for Libtool
AM_LIBTOOLFLAGS = --preserve-dup-deps

# Flags for pthread
PTHREAD_FLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)

# Define different types of programs to build
bin_PROGRAMS =
noinst_PROGRAMS =
check_PROGRAMS =

# Define library target
lib_LTLIBRARIES = libqyra.la
noinst_LTLIBRARIES =

# Header file to be installed for public API access
include_HEADERS = include/qyra.h include/common.h

# Include directories
QYRA_INCLUDES=-I$(builddir) -I$(srcdir)/include -I$(srcdir)/test -I$(srcdir)/bench

QYRA_API_H = \
	include/qyra.h

QYRA_COMMON_H = \
	include/common.h

QYRA_H = \
	crypto.h \
	hash.h \
	graph.h \
	path.h \
	stream.h \
	utils.h

# Source files for the libqyra library
libqyra_la_SOURCES = \
	crypto.cpp \
	hash.cpp \
	graph.cpp \
	path.cpp \
	utils.cpp \
	qyra.cpp \
	$(QYRA_H) \
	$(QYRA_API_H) \
	$(QYRA_COMMON_H)

# Preprocessor flags for libqyra
libqyra_la_CPPFLAGS = $(AM_CPPFLAGS) $(QYRA_INCLUDES)

# C++ flags for libqyra
libqyra_la_CXXFLAGS = $(AM_CXXFLAGS)

# Linking flags for libqyra
libqyra_la_LDFLAGS  = $(AM_LDFLAGS) $(PTHREAD_FLAGS) $(LIBTOOL_APP_LDFLAGS) -no-undefined

# Additional libraries to link with libqyra
libqyra_la_LIBADD   = $(LIBBLAKE3_LIBS) $(LIBOQS_LIBS) $(LIBCRYPTO_LIBS) $(OPENSSL_LIBS)

# Versioning information for libqyra
libqyra_la_LDFLAGS += -version-info $(QYRA_VERSION_MAJOR):$(QYRA_VERSION_MINOR):0

# AVX2
if ENABLE_AVX2
libqyra_la_CPPFLAGS += -DOQS_ENABLE_AVX2
libqyra_la_CXXFLAGS += $(AVX2_CXXFLAGS)
endif

# Files to clean during `make clean`
CLEANFILES = *.gcda *.gcno

# Include keygen Makefile if keygen is enabled
if ENABLE_KEYGEN
include Makefile.keygen.include
endif

# Include benchmarking Makefile if benchmarking is enabled
if ENABLE_BENCH
include Makefile.bench.include
endif

# Include testing Makefile if testing is enabled
if ENABLE_TEST
include Makefile.test.include
endif
dnl Copyright (c) 2024 Marco Fortina
dnl Distributed under the MIT software license, see the accompanying
dnl file COPYING or https://www.opensource.org/licenses/mit-license.php.

dnl Define the minimum required Autoconf version
AC_PREREQ([2.69])

dnl Define version numbers
define(_QYRA_VERSION_MAJOR, 1)
define(_QYRA_VERSION_MINOR, 0)
define(_QYRA_VERSION_BUILD, 0)

dnl Initialize the package, specifying the version and contact information
AC_INIT([Qyra Library], m4_join([.], _QYRA_VERSION_MAJOR, _QYRA_VERSION_MINOR, _QYRA_VERSION_BUILD), [https://github.com/marcofortina/qyra/issues], [libqyra], [https://github.com/marcofortina/qyra])

dnl Specify the source directory and header file
AC_CONFIG_SRCDIR([src/qyra.cpp])
AC_CONFIG_HEADERS([src/config/qyra-config.h])

dnl Set up auxiliary directories for configuration
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])

dnl Ensure pkg-config is available
m4_ifndef([PKG_PROG_PKG_CONFIG], [m4_fatal([PKG_PROG_PKG_CONFIG macro not found. Please install pkg-config and re-run autogen.sh])])
PKG_PROG_PKG_CONFIG
if test "$PKG_CONFIG" = ""; then
  AC_MSG_ERROR([pkg-config not found])
fi

dnl Canonicalize the host system type
AC_CANONICAL_HOST

dnl Setup header guard for config.h
AH_TOP([#ifndef QYRA_CONFIG_H])
AH_TOP([#define QYRA_CONFIG_H])
AH_BOTTOM([#endif //QYRA_CONFIG_H])

dnl Automake init set-up and checks
AM_INIT_AUTOMAKE([1.13 no-define subdir-objects foreign])

dnl Enable maintainer mode
AM_MAINTAINER_MODE([enable])

dnl make the compilation flags quiet unless V=1 is used
AM_SILENT_RULES([yes])

dnl Compiler checks (here before libtool).
if test "${CXXFLAGS+set}" = "set"; then
  CXXFLAGS_overridden=yes
else
  CXXFLAGS_overridden=no
fi

dnl Detect C++ compiler
AC_PROG_CXX

dnl Require C++20 compiler (no GNU extensions)
AX_CXX_COMPILE_STDCXX([20], [noext], [mandatory])

dnl Unless the user specified OBJCXX, force it to be the same as CXX. This ensures
dnl that we get the same -std flags for both.
m4_ifdef([AC_PROG_OBJCXX], [
if test "${OBJCXX+set}" = ""; then
  OBJCXX="${CXX}"
fi
AC_PROG_OBJCXX
])

dnl OpenBSD ships with 2.4.2
LT_PREREQ([2.4.2])
dnl Libtool init checks.
LT_INIT([pic-only win32-dll])

dnl Check/return PATH for base programs.
AC_PATH_TOOL([AR], [ar])
AC_PATH_PROGS([PYTHON], [python3.9 python3.10 python3.11 python3.12 python3 python])
AC_PATH_PROG([DOXYGEN], [doxygen])
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])

dnl Enable keygen
AC_ARG_ENABLE(keygen,
  AS_HELP_STRING([--disable-keygen],
                 [do not compile keygen (default is to compile)]),
  [use_keygen=$enableval],
  [use_keygen=yes])

dnl Enable benchmarks
AC_ARG_ENABLE(bench,
  AS_HELP_STRING([--disable-bench],
                 [do not compile benchmarks (default is to compile)]),
  [use_bench=$enableval],
  [use_bench=yes])

dnl Enable tests
AC_ARG_ENABLE(tests,
  AS_HELP_STRING([--disable-tests],
                 [do not compile tests (default is to compile)]),
  [use_tests=$enableval],
  [use_tests=yes])

dnl Enable debug
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
                  [use compiler flags and macros suited for debugging (default is no)])],
  [enable_debug=$enableval],
  [enable_debug=no])

dnl Turn warnings into errors
AC_ARG_ENABLE([werror],
  [AS_HELP_STRING([--enable-werror],
                  [Treat compiler warnings as errors (default is no)])],
  [enable_werror=$enableval],
  [enable_werror=no])

dnl Check for libblake3
PKG_CHECK_MODULES([LIBBLAKE3], [libblake3], [have_blake3=yes], [have_blake3=no])
if test "$have_blake3" = "no"; then
  AC_MSG_ERROR([libblake3 required but libblake3 is not available])
fi

dnl Check for libcrypto
PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto], [have_crypto=yes], [have_crypto=no])
if test "$have_crypto" = "no"; then
  AC_MSG_ERROR([libcrypto required but libcrypto is not available])
fi

dnl Check for liboqs
PKG_CHECK_MODULES([LIBOQS], [liboqs >= 0.9], [have_oqs=yes], [have_oqs=no])
if test "$have_oqs" = "no"; then
  AC_MSG_ERROR([liboqs required but liboqs is not available])
fi

dnl Check for libssl
AX_CHECK_OPENSSL([have_openssl=yes], [have_openssl=no])
if test "$have_openssl" = "no"; then
  AC_MSG_ERROR([libssl required but libssl is not available])
fi

dnl Ensure C++ language settings
AC_LANG_PUSH([C++])

dnl Always set -g -O2 in our CXXFLAGS. Autoconf will try and set CXXFLAGS to "-g -O2" by default,
dnl so we suppress that (if CXXFLAGS hasn't been overridden by the user), given we are adding it
dnl ourselves.
CXXFLAGS="$CXXFLAGS -g -O2"
if test "$CXXFLAGS_overridden" = "no"; then
  CXXFLAGS="-g -O2"
fi

dnl Check for a flag to turn compiler warnings into errors. This is helpful for checks which may
dnl appear to succeed because by default they merely emit warnings when they fail.
dnl
dnl Note that this is not necessarily a check to see if -Werror is supported, but rather to see if
dnl a compile with -Werror can succeed. This is important because the compiler may already be
dnl warning about something unrelated, for example about some path issue. If that is the case,
dnl -Werror cannot be used because all of those warnings would be turned into errors.
AX_CHECK_COMPILE_FLAG([-Werror], [CXXFLAG_WERROR="-Werror"], [CXXFLAG_WERROR=""])

dnl Configure debug flags
if test "$enable_debug" = "yes"; then
  dnl Disable all optimizations
  AX_CHECK_COMPILE_FLAG([-O0], [DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -O0"], [], [$CXXFLAG_WERROR])

  dnl Prefer -g3, fall back to -g if that is unavailable.
  AX_CHECK_COMPILE_FLAG(
    [-g3],
    [DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -g3"],
    [AX_CHECK_COMPILE_FLAG([-g], [DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -g"], [], [$CXXFLAG_WERROR])],
    [$CXXFLAG_WERROR])

  AX_CHECK_PREPROC_FLAG([-DDEBUG], [DEBUG_CPPFLAGS="$DEBUG_CPPFLAGS -DDEBUG"], [], [$CXXFLAG_WERROR])
fi

dnl Define error flags for the compiler
ERROR_CXXFLAGS=
if test "$enable_werror" = "yes"; then
  if test "$CXXFLAG_WERROR" = ""; then
    AC_MSG_ERROR([enable-werror set but -Werror is not usable])
  fi
  ERROR_CXXFLAGS=$CXXFLAG_WERROR
fi

dnl Configure warning flags
AX_CHECK_COMPILE_FLAG([-Wall], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wall"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wextra], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wextra"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wgnu], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wgnu"], [], [$CXXFLAG_WERROR])
dnl some compilers will ignore -Wformat-security without -Wformat, so just combine the two here.
AX_CHECK_COMPILE_FLAG([-Wformat -Wformat-security], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wformat -Wformat-security"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wvla], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wvla"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wshadow-field], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wshadow-field"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wthread-safety], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wthread-safety"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wloop-analysis], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wloop-analysis"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wredundant-decls], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wredundant-decls"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wunused-member-function], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wunused-member-function"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wdate-time], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wdate-time"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wconditional-uninitialized], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wconditional-uninitialized"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wduplicated-branches], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wduplicated-branches"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wduplicated-cond], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wduplicated-cond"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wlogical-op], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wlogical-op"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Woverloaded-virtual], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Woverloaded-virtual"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wsuggest-override], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wsuggest-override"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wimplicit-fallthrough], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wimplicit-fallthrough"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wunreachable-code], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wunreachable-code"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wdocumentation], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wdocumentation"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wself-assign], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wself-assign"], [], [$CXXFLAG_WERROR])
AX_CHECK_COMPILE_FLAG([-Wundef], [WARN_CXXFLAGS="$WARN_CXXFLAGS -Wundef"], [], [$CXXFLAG_WERROR])

dnl Some compilers (gcc) ignore unknown -Wno-* options, but warn about all
dnl unknown options if any other warning is produced. Test the -Wfoo case, and
dnl set the -Wno-foo case if it works.
AX_CHECK_COMPILE_FLAG([-Wunused-parameter], [NOWARN_CXXFLAGS="$NOWARN_CXXFLAGS -Wno-unused-parameter"], [], [$CXXFLAG_WERROR])

dnl Don't allow extended (non-ASCII) symbols in identifiers. This is easier for code review.
AX_CHECK_COMPILE_FLAG([-fno-extended-identifiers], [CXXFLAGS="$CXXFLAGS -fno-extended-identifiers"], [], [$CXXFLAG_WERROR])

dnl Currently all versions of gcc are subject to a class of bugs, see the
dnl gccbug_90348 test case (only reproduces on GCC 11 and earlier) and
dnl https://gcc.gnu.org/bugzilla/show_bug.cgi?id=111843. To work around that, set
dnl -fstack-reuse=none for all gcc builds. (Only gcc understands this flag)
AX_CHECK_COMPILE_FLAG([-fstack-reuse=none], [CXXFLAGS="$CXXFLAGS -fstack-reuse=none"])

dnl Check for endianness
AC_C_BIGENDIAN

dnl Check for pthread compile/link requirements
AX_PTHREAD

dnl Check for optional instruction set support. Enabling these does _not_ imply that all code will
dnl be compiled with them, rather that specific objects/libs may use them after checking for runtime
dnl compatibility.

enable_avx2=no

dnl x86
AX_CHECK_COMPILE_FLAG([-mavx -mavx2], [AVX2_CXXFLAGS="-mavx -mavx2"])

dnl AVX2
TEMP_CXXFLAGS="$CXXFLAGS"
CXXFLAGS="$AVX2_CXXFLAGS $CXXFLAGS"
AC_MSG_CHECKING([for AVX2 intrinsics])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <stdint.h>
    #include <immintrin.h>
  ]],[[
    __m256i l = _mm256_set1_epi32(0);
    return _mm256_extract_epi32(l, 7);
  ]])],
 [ AC_MSG_RESULT([yes]); enable_avx2=yes; AC_DEFINE([ENABLE_AVX2], [1], [Define this symbol to build code that uses AVX2 intrinsics]) ],
 [ AC_MSG_RESULT([no])]
)
CXXFLAGS="$TEMP_CXXFLAGS"
AM_CONDITIONAL([ENABLE_AVX2], [test "$enable_avx2" = "yes"])

dnl Set conditions for enabling keygen
AC_MSG_CHECKING([whether to build qyra-keygen])
AM_CONDITIONAL([ENABLE_KEYGEN], [test $use_keygen = "yes"])
AC_MSG_RESULT($use_keygen)

dnl Set conditions for enabling benchmarks
AC_MSG_CHECKING([whether to build qyra-bench])
AM_CONDITIONAL([ENABLE_BENCH], [test "$use_bench" = "yes"])
AC_MSG_RESULT($use_bench)

dnl Set conditions for enabling tests
AC_MSG_CHECKING([whether to build qyra-test])
AM_CONDITIONAL([ENABLE_TEST], [test "$use_tests" = "yes"])
AC_MSG_RESULT($use_tests)

dnl Check for Boost headers
if test "$use_tests" = "yes"; then
  AX_BOOST_BASE([1.73.0], [], [AC_MSG_ERROR([Boost is not available!])])
  if test "$want_boost" = "no"; then
    AC_MSG_ERROR([Boost is required])
  fi
fi

if test "$use_bench" = "yes"; then
  if test "$PYTHON" = ""; then
    AC_MSG_ERROR([python is required for benchmarks])
  fi
fi

dnl Define version macros
AC_DEFINE([QYRA_VERSION_MAJOR], [_QYRA_VERSION_MAJOR], [Major version])
AC_DEFINE([QYRA_VERSION_MINOR], [_QYRA_VERSION_MINOR], [Minor version])
AC_DEFINE([QYRA_VERSION_BUILD], [_QYRA_VERSION_BUILD], [Version Build])

dnl Substitute version numbers and other variables
AC_SUBST(QYRA_VERSION_MAJOR, _QYRA_VERSION_MAJOR)
AC_SUBST(QYRA_VERSION_MINOR, _QYRA_VERSION_MINOR)
AC_SUBST(QYRA_VERSION_BUILD, _QYRA_VERSION_BUILD)
AC_SUBST(AVX2_CXXFLAGS)
AC_SUBST(WARN_CXXFLAGS)
AC_SUBST(NOWARN_CXXFLAGS)
AC_SUBST(ERROR_CXXFLAGS)
AC_SUBST(DEBUG_CXXFLAGS)
AC_SUBST(DEBUG_CPPFLAGS)
AC_SUBST(LIBTOOL_APP_LDFLAGS)
AC_SUBST(LIBBLAKE3_LIBS)
AC_SUBST(LIBCRYPTO_LIBS)
AC_SUBST(LIBOQS_LIBS)
AC_SUBST(OPENSSL_LIBS)

dnl Create Makefile templates
AC_CONFIG_FILES([Makefile src/Makefile])
AC_CONFIG_FILES([libqyra.pc:libqyra.pc.in])

dnl Configure the Doxyfile for generating documentation
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([doc/Doxyfile])])

dnl Generate necessary build files
AC_OUTPUT

dnl Print configuration summary
echo
echo "Options used to compile and link:"
echo "  with boost      = $want_boost"
echo "  with bench      = $use_bench"
echo "  with keygen     = $use_keygen"
echo "  with test       = $use_tests"
echo
echo "  avx2 enabled    = $enable_avx2"
echo "  debug enabled   = $enable_debug"
echo "  werror          = $enable_werror"
echo
echo "  target os       = $host_os"
echo "  build os        = $build_os"
echo
echo "  CC              = $CC"
echo "  CFLAGS          = $PTHREAD_CFLAGS $OPENSSL_INCLUDES $CFLAGS"
echo "  CPPFLAGS        = $CPPFLAGS $DEBUG_CPPFLAGS $BOOST_CPPFLAGS"
echo "  CXX             = $CXX"
echo "  CXXFLAGS        = $DEBUG_CXXFLAGS $WARN_CXXFLAGS $NOWARN_CXXFLAGS $ERROR_CXXFLAGS $AVX2_CXXFLAGS $CXXFLAGS"
echo "  LDFLAGS         = $PTHREAD_LIBS $LIBBLAKE3_LIBS $LIBOQS_LIBS $LIBCRYPTO_LIBS $OPENSSL_LDFLAGS $OPENSSL_LIBS $LDFLAGS"
echo "  AR              = $AR"
echo "  ARFLAGS         = $ARFLAGS"
echo

dnl Provide a message about the completion of the configuration
AC_MSG_NOTICE([Configuration completed successfully.])
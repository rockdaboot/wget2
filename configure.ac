dnl Template file for GNU Autoconf
dnl Copyright (C) 2015-2022 Free Software Foundation, Inc.

dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.

dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.

dnl You should have received a copy of the GNU General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Process this file with autoconf to produce a configure script.

dnl Error if AX_CODE_COVERAGE if missing.
m4_pattern_forbid([^_?AX_])
m4_pattern_allow([AX_CHECK_GNU_MAKE_HEADLINE])
m4_pattern_allow([_AX_CODE_COVERAGE_GCOV_PROG_WITH])

CFLAGS=$CFLAGS
LDFLAGS=$LDFLAGS

AC_PREREQ([2.69])
AC_INIT([wget2],[2.0.1],[bug-wget@gnu.org],[wget2],[https://savannah.gnu.org/projects/wget])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([subdir-objects parallel-tests gnu -Wno-portability dist-lzip])

AC_CANONICAL_HOST
case $host_os in
  linux*)
    ;;
  mingw*)
    XTRA_CFLAGS="-Wno-attributes -fno-PIC"
#    XTRA_LIBS=-lws2_32
    ;;
  cygwin*)
    XTRA_CFLAGS="-Wno-char-subscripts -fno-PIC"
    ;;
#  *)
#    AC_MSG_ERROR([$host_os is not currently supported])
#    ;;
esac

# Append EXTRA_CFLAGS to CFLAGS, if defined.
test -n "$EXTRA_CFLAGS" && CFLAGS="$CFLAGS $EXTRA_CFLAGS"
test -n "$XTRA_CFLAGS" && CFLAGS="$CFLAGS $XTRA_CFLAGS"

AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
if test "$ac_cv_prog_cc_c99" = "no"; then
  AC_MSG_ERROR(Compiler does not support C99. Aborting.)
fi

gl_EARLY
gl_INIT

AX_CODE_COVERAGE

LT_PREREQ([2.2])
LT_INIT([dlopen])

# Define these substitutions here to keep all version information in one place.
# For information on how to properly maintain the library version information,
# refer to the libtool manual, section "Updating library version information":
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
#
# 1. Start with version information of ‘0:0:0’ for each libtool library.
# 2. Update the version information only immediately before a public release of your software. More frequent updates are unnecessary, and only guarantee that the current interface number gets larger faster.
# 3. If the library source code has changed at all since the last update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# 4. If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
# 5. If any interfaces have been added since the last public release, then increment age.
# 6. If any existing interfaces have been removed or changed since the last public release, then set age to 0.
AC_SUBST([LIBWGET_SO_VERSION], [1:0:0])
AC_SUBST([LIBWGET_VERSION], [2.1.0])

#
# Generate version defines for include file
#
AC_SUBST([LIBWGET_VERSION_MAJOR], [`echo $LIBWGET_VERSION|cut -d'.' -f1`])
AC_SUBST([LIBWGET_VERSION_MINOR], [`echo $LIBWGET_VERSION|cut -d'.' -f2`])
AC_SUBST([LIBWGET_VERSION_PATCH], [`echo $LIBWGET_VERSION|cut -d'.' -f3`])
AC_SUBST([LIBWGET_VERSION_NUMBER], [`printf '0x%02x%02x%02x' $LIBWGET_VERSION_MAJOR $LIBWGET_VERSION_MINOR $LIBWGET_VERSION_PATCH`])
AC_CONFIG_FILES([include/wget/wgetver.h])

AC_CONFIG_SRCDIR([src/wget.c])
AC_CONFIG_HEADERS([config.h])

# Non-verbose make
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Check for large file support.  This check needs to come fairly
# early because it could (in principle) affect whether functions and
# headers are available, whether they work, etc.
AC_SYS_LARGEFILE
AC_CHECK_SIZEOF(off_t)

# Checks for programs.

AC_PROG_LEX([noyywrap])
AC_PROG_INSTALL
AC_PROG_LN_S

# enable all possible compiler warnings in WARN_FLAGS
#
# to enable by default: create a file '.manywarnings'
# enable explicitly : ./configure --enable-manywarnings
# disable explicitly: ./configure --disable-manywarnings
wget_MANYWARNINGS(WARN_CFLAGS, C)

if test -n "$WARN_CFLAGS"; then
  if test "$CCNAME" = "gcc"; then
    # Set up list of unwanted warnings
    nw=
    nw="$nw -Wsystem-headers"       # System headers may trigger lot's of useless warnings
    nw="$nw -Wvla"                  # This project is C99
    nw="$nw -Wstack-protector"
    nw="$nw -Wmissing-field-initializer"
    nw="$nw -Wtraditional"
    nw="$nw -Wtraditional-conversion"
    nw="$nw -Wc++-compat"
    nw="$nw -Wcast-qual"
    nw="$nw -Wconversion"
    nw="$nw -Wsign-conversion"
    nw="$nw -Wunsuffixed-float-constants"
    nw="$nw -Wdeclaration-after-statement" # C89 only, messing up gcc < 5
    nw="$nw -Wcast-function-type" # gcc 8, very noisy
    nw="$nw -Wabi" # gcc 8, very noisy
    nw="$nw -Wunused-macros" # triggers in auto-generated lex css parser, #pragma doesn't work, conflicts with -Werror
    nw="$nw -Wchkp" # gcc-9 says: not supported any more (but emits it via -Q --help=C)"
    if test "$cross_compiling" = yes; then
      nw="$nw -Wformat"
    fi

    # remove unwanted warn flags
    wget_WORD_REMOVE([WARN_CFLAGS], [$WARN_CFLAGS], [$nw])

    # add more flags as you like
    if test $GCC_VERSION -ge 5; then
      WARN_CFLAGS="$WARN_CFLAGS -fdiagnostics-color=always"
    fi
    if test "$cross_compiling" = yes; then
      WARN_CFLAGS="$WARN_CFLAGS -Wno-format"
    fi
    if test $GCC_VERSION -ge 8; then
      WARN_CFLAGS="$WARN_CFLAGS -Wno-cast-function-type"
    fi
    # WARN_CFLAGS="$WARN_CFLAGS -Werror"

    # We use a slightly smaller set of warning options for lib/.
    # Remove the following and save the result in GNULIB_WARN_CFLAGS.
    # Removing is not enough if these switches are implicitly set by other
    #  flags like -Wall or -Wextra. We have to explicitly unset them
    #  with -Wno-....
    nw=
    nw="$nw -Wpedantic"
    nw="$nw -Wsign-compare"
    nw="$nw -Wunused-parameter"
    nw="$nw -Wswitch-default"
    nw="$nw -Wformat-nonliteral"
    nw="$nw -Wsuggest-attribute=pure"
    nw="$nw -Wunsafe-loop-optimizations"
    nw="$nw -Wundef"
    nw="$nw -Wswitch-enum"
    nw="$nw -Wbad-function-cast"
    nw="$nw -Wredundant-decls"
    nw="$nw -Werror"
    wget_WORD_REMOVE([GNULIB_WARN_CFLAGS], [$WARN_CFLAGS], [$nw])
    wget_WORD_REMOVE([CFLAGS], [$CFLAGS], [-Werror])

    # disable options implicitly set by other options
    GNULIB_WARN_CFLAGS="-Wno-error $GNULIB_WARN_CFLAGS"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-sign-compare -Wno-unused-parameter -Wno-alloca"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-float-conversion -Wno-cast-function-type"
    if test "$cross_compiling" = yes; then
      GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-incompatible-pointer-types"
    fi

  elif test "$CCNAME" = "clang"; then
    # setup flags for this project
    WARN_CFLAGS="$WARN_CFLAGS -Wno-system-headers -Wno-vla -Wno-cast-qual -Wno-padded"
    WARN_CFLAGS="$WARN_CFLAGS -Wno-reserved-id-macro -Wno-sign-conversion  -Wno-disabled-macro-expansion"
    WARN_CFLAGS="$WARN_CFLAGS -Wno-documentation -Wno-documentation-unknown-command"
    WARN_CFLAGS="$WARN_CFLAGS -Wno-covered-switch-default -Wno-unused-macros"
    WARN_CFLAGS="$WARN_CFLAGS -Wno-missing-field-initializers"
    WARN_CFLAGS="$WARN_CFLAGS -Wno-nullability-extension -Wno-nullability-completeness"

    CLANG_VERSION=$($CC -dumpversion | cut -f1 -d.)
    if test $CLANG_VERSION -ge 11; then
      WARN_CFLAGS="$WARN_CFLAGS -Wno-implicit-int-float-conversion"
    fi

    if test $CLANG_VERSION -ge 12; then
      WARN_CFLAGS="$WARN_CFLAGS -Wno-string-concatenation"
    fi

    if test $CLANG_VERSION -ge 13; then
      WARN_CFLAGS="$WARN_CFLAGS -Wno-reserved-identifier"
    fi

    # remove all flags from WARN_FLAGS that are already in CFLAGS
    # wget_WORD_REMOVE([WARN_CFLAGS], [$WARN_CFLAGS], [$CFLAGS])

    wget_WORD_REMOVE([CFLAGS], [$CFLAGS], [-Werror])

    # disable verbose options
    GNULIB_WARN_CFLAGS="-Wno-error $GNULIB_WARN_CFLAGS"
    GNULIB_WARN_CFLAGS="$WARN_CFLAGS -Wno-sign-compare -Wno-unused-parameter -Wno-undef -Wno-format-nonliteral"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-conversion -Wno-disabled-macro-expansion -Wno-c++98-compat"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-gnu-statement-expression -Wno-shorten-64-to-32 -Wno-switch-enum"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-unused-macros -Wno-missing-field-initializers"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-gnu-zero-variadic-macro-arguments -Wno-conditional-uninitialized"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-comma -Wno-assign-enum -Wno-unreachable-code -Wno-error"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-missing-field-initializers -Wno-used-but-marked-unused"

    # remove all flags from GNULIB_WARN_FLAGS that are already in CFLAGS
    # wget_WORD_REMOVE([GNULIB_WARN_CFLAGS], [$GNULIB_WARN_CFLAGS], [$CFLAGS])
  fi

  AC_SUBST([MANYWARNINGS], [-DWGET_MANYWARNINGS])
  AC_SUBST([WARN_CFLAGS])
  AC_SUBST([GNULIB_WARN_CFLAGS])
fi

AC_ARG_ENABLE([manylibs],
  [AS_HELP_STRING([--enable-manylibs], [Generate small libraries of libwget functionality groups])],
  [enable_manylibs=$enableval], [enable_manylibs=no])
AM_CONDITIONAL([ENABLE_MANYLIBS], [test "$enable_manylibs" = "yes"])

AC_ARG_ENABLE([fuzzing],
  [AS_HELP_STRING([--enable-fuzzing], [Turn on fuzzing build (for developers)])],
  [enable_fuzzing=yes; AC_SUBST([LIB_FUZZING_ENGINE])], [enable_fuzzing=no; LIB_FUZZING_ENGINE=""])
AM_CONDITIONAL([FUZZING], [test -n "$LIB_FUZZING_ENGINE"])

AC_ARG_ENABLE([fsanitize-ubsan],
  [AS_HELP_STRING([--enable-fsanitize-ubsan], [Turn on Undefined Behavior Sanitizer (for developers)])],
  [gl_cc_sanitize_ubsan=yes], [gl_cc_sanitize_ubsan=no])

AC_ARG_ENABLE([fsanitize-asan],
  [AS_HELP_STRING([--enable-fsanitize-asan], [Turn on Address Sanitizer (for developers) (mutually exclusive with Memory/Thread sanitizer or Valgrind tests)])],
  [gl_cc_sanitize_asan=yes], [gl_cc_sanitize_asan=no])

AC_ARG_ENABLE([fsanitize-msan],
  [AS_HELP_STRING([--enable-fsanitize-msan], [Turn on Memory Sanitizer (for developers) (mutually exclusive with Address/Thread sanitizer or Valgrind tests)])],
  [gl_cc_sanitize_msan=yes], [gl_cc_sanitize_msan=no])

AC_ARG_ENABLE([fsanitize-tsan],
  [AS_HELP_STRING([--enable-fsanitize-tsan], [Turn on Thread Sanitizer (for developers) (mutually exclusive with Address/Memory sanitizer or Valgrind tests)])],
  [gl_cc_sanitize_tsan=yes], [gl_cc_sanitize_tsan=no])


if test "$gl_cc_sanitize_asan" = yes; then
  if test "$gl_cc_sanitize_msan" = yes; then
    AC_MSG_ERROR([Address Sanitizer and Memory Sanitizer are mutually exclusive])
  elif test "$gl_cc_sanitize_tsan" = yes; then
    AC_MSG_ERROR([Address Sanitizer and Thread Sanitizer are mutually exclusive])
  fi
fi


if test "$gl_cc_sanitize_msan" = yes; then
  if test "$gl_cc_sanitize_tsan" = yes; then
    AC_MSG_ERROR([Memory Sanitizer and Thread Sanitizer are mutually exclusive])
  fi
fi


if test "$gl_cc_sanitize_ubsan" = yes; then
  gl_WARN_ADD([-fsanitize=undefined])
  gl_WARN_ADD([-fsanitize=bool])
  gl_WARN_ADD([-fsanitize=alignment])
  gl_WARN_ADD([-fsanitize=null])
  gl_WARN_ADD([-fsanitize=enum])
  gl_WARN_ADD([-fsanitize=bounds-strict])

  # additional clang options, from OSS-Fuzz (20.12.2019)
  gl_WARN_ADD([-fsanitize=integer])
  gl_WARN_ADD([-fsanitize=array-bounds])
  gl_WARN_ADD([-fsanitize=builtin])
  gl_WARN_ADD([-fsanitize=float-divide-by-zero])
  gl_WARN_ADD([-fsanitize=function])
  gl_WARN_ADD([-fsanitize=integer-divide-by-zero])
  gl_WARN_ADD([-fsanitize=object-size])
  gl_WARN_ADD([-fsanitize=return])
  gl_WARN_ADD([-fsanitize=returns-nonnull-attribute])
  gl_WARN_ADD([-fsanitize=shift])
  gl_WARN_ADD([-fsanitize=signed-integer-overflow])
  gl_WARN_ADD([-fsanitize=unsigned-integer-overflow])
  gl_WARN_ADD([-fsanitize=unreachable])
  gl_WARN_ADD([-fsanitize=vla-bound])
  gl_WARN_ADD([-fsanitize=vptr])
fi

if test "$gl_cc_sanitize_asan" = yes; then
  gl_WARN_ADD([-fsanitize=address])
  gl_WARN_ADD([-fsanitize=leak])
  gl_WARN_ADD([-fsanitize=nonnull-attribute])
  gl_WARN_ADD([-fno-omit-frame-pointer])

  # additional clang option
  gl_WARN_ADD([-fsanitize-address-use-after-scope])
fi

if test "$gl_cc_sanitize_ubsan" = yes || test "$gl_cc_sanitize_asan" = yes; then
  gl_WARN_ADD([-fno-sanitize-recover=all])
  gl_WARN_ADD([-fsanitize-recover=unsigned-integer-overflow])
fi

if test "$gl_cc_sanitize_msan" = yes; then
  # clang options
  gl_WARN_ADD([-fsanitize=memory])
  gl_WARN_ADD([-fsanitize-memory-track-origins])

  # gcc options
  if test "$CCNAME" = "gcc"; then
    gl_WARN_ADD([-fsanitize=leak])
  fi

  gl_WARN_ADD([-fno-omit-frame-pointer])
  gl_WARN_ADD([-fPIE])
fi

if test "$gl_cc_sanitize_tsan" = yes; then
  gl_WARN_ADD([-fsanitize=thread -fPIC -pie])
fi

#
# Assertions
#
AC_ARG_ENABLE([assert],
  [AS_HELP_STRING([--enable-assert], [Enable assertions in code (for developers)])],
  [ENABLE_ASSERT=$enableval], [ENABLE_ASSERT=no])

AS_IF([test "$ENABLE_ASSERT" != "yes"], [CFLAGS="-DNDEBUG $CFLAGS"], [])

#
# xattr
#
AC_ARG_ENABLE([xattr],
  [AS_HELP_STRING([--disable-xattr], [disable support for POSIX Extended Attributes])],
  [ENABLE_XATTR=$enableval; xattr_requested=$enableval],
  [ENABLE_XATTR=yes])

if test "${ENABLE_XATTR}" = "yes" ; then
  case "$host_os" in
    *linux* | *darwin*)
      AC_CHECK_FUNCS([fsetxattr], [], [
        AC_MSG_NOTICE([Disabling Extended Attribute support: your system does not support fsetxattr])
        ENABLE_XATTR=no
      ])
      ;;
    freebsd*)
      AC_CHECK_FUNCS([extattr_set_fd], [], [
        AC_MSG_NOTICE([Disabling Extended Attribute support: your system does not support extattr_set_fd])
        ENABLE_XATTR=no
      ])
      ;;
    *)
      AC_MSG_NOTICE([Disabling Extended Attribute support: your system is not known to support extended attributes.])
      ENABLE_XATTR=no
  esac

  if test "$ENABLE_XATTR" = "no" && test "$xattr_requested" = "yes"; then
    AC_MSG_ERROR([Extended Attributes (xattr) have been requested but are not available.])
  fi
fi

test "${ENABLE_XATTR}" = "yes" && AC_DEFINE([ENABLE_XATTR], 1,
    [Define if you want file meta-data storing into POSIX Extended Attributes compiled in.])

#
# Gettext
#
m4_ifdef([AM_GNU_GETTEXT], [
  AM_GNU_GETTEXT([external],[need-ngettext])
  AC_CONFIG_FILES([po/Makefile.in])
  have_po=yes
], [
  have_po=no
])
m4_ifdef([AM_GNU_GETTEXT_VERSION], [
#do not indent here
AM_GNU_GETTEXT_VERSION([0.19.3])
])
AM_CONDITIONAL([HAVE_PO], [ test "$have_po" = "yes" ])

#
# check for doxygen and pandoc
#
AC_ARG_ENABLE(doc, AS_HELP_STRING([--disable-doc], [don t generate any documentation]),
  enable_doc=$enableval, enable_doc=yes)
if test "$enable_doc" = yes; then
  AC_CHECK_PROGS([DOXYGEN], [doxygen])
  AC_CHECK_PROGS([PANDOC], [pandoc])

  if test -n "$DOXYGEN" || test -n "$PANDOC"; then
    DOCS_INFO="yes"
    LIBWGET_DOCS_INFO="yes (found:"
    if test -n "$DOXYGEN"; then
      LIBWGET_DOCS_INFO="$LIBWGET_DOCS_INFO Doxygen)"
    else
      LIBWGET_DOCS_INFO="no"
    fi
    WGET2_DOCS_INFO="yes (found:"
    if test -n "$PANDOC"; then
      WGET2_DOCS_INFO="$WGET2_DOCS_INFO Pandoc)"
    else
      WGET2_DOCS_INFO="no"
    fi
  else
    DOCS_INFO="no (neither Doxygen nor Pandoc found)"
  fi
else
  DOCS_INFO="no (disabled)"
fi
AM_CONDITIONAL([WITH_DOCS], [ test -n "$DOXYGEN" || test -n "$PANDOC" ])
AM_CONDITIONAL([WITH_DOXYGEN], [ test -n "$DOXYGEN" ])
AM_CONDITIONAL([WITH_PANDOC], [ test -n "$PANDOC" ])

#
# enable creation of man pages
#
#AC_ARG_ENABLE(man,[AS_HELP_STRING([--enable-man],
#                                  [generate man pages [default=auto]])],enable_man=yes,enable_man=no)

#AM_CONDITIONAL(ENABLE_MAN, test "$enable_man" != "no")
#AC_MSG_CHECKING([whether to generate man pages])
#AS_IF([test "$enable_man" != no], [
#  AC_MSG_RESULT([yes])
#], [
#  AC_MSG_RESULT([no])
#])


# Check for ldconfig
AC_CHECK_PROG(LDCONFIG, ldconfig, ldconfig, :)

# Check for valgrind
AC_ARG_ENABLE(valgrind-tests,
  AS_HELP_STRING([--enable-valgrind-tests], [enable using Valgrind for tests (mutually exclusive with Address/Memory/Thread sanitizer)]),
  [ac_enable_valgrind=$enableval], [ac_enable_valgrind=no])
AS_IF([test "${ac_enable_valgrind}" != "no"], [
  AC_CHECK_PROG(HAVE_VALGRIND, valgrind, yes, no)
  AS_IF([test "$HAVE_VALGRIND" = "yes"], [
    VALGRIND_TESTS="1"
    AC_SUBST(VALGRIND_TESTS)
    TESTS_INFO="Test suite will be run under Valgrind"
  ], [
    TESTS_INFO="Valgrind not found"
  ])
], [
  TESTS_INFO="Valgrind testing not enabled"
])


if test "$VALGRIND_TESTS" = 1; then
  if test "$gl_cc_sanitize_asan" = yes; then
    AC_MSG_ERROR([Valgrind and Address Sanitizer are mutually exclusive])
  elif test "$gl_cc_sanitize_msan" = yes; then
    AC_MSG_ERROR([Valgrind and Memory Sanitizer are mutually exclusive])
  elif test "$gl_cc_sanitize_tsan" = yes; then
    AC_MSG_ERROR([Valgrind and Thread Sanitizer are mutually exclusive])
  fi
fi

# check for pandoc (documentation converter)

# check for gcc's atomic read-add-write functionality
AC_MSG_CHECKING([for __sync_fetch_and_add (int)])
AC_LINK_IFELSE(
   [AC_LANG_SOURCE([
    int main(void) { return __sync_fetch_and_add((int *)0, 0); }
   ])],
   [AC_DEFINE([WITH_SYNC_FETCH_AND_ADD], [1], [use __sync_fetch_and_add]) AC_MSG_RESULT([yes])],
   [AC_MSG_RESULT([no])]
)
AC_MSG_CHECKING([for __sync_fetch_and_add (long long)])
AC_LINK_IFELSE(
   [AC_LANG_SOURCE([
    int main(void) { return __sync_fetch_and_add((long long *)0, 0); }
   ])],
   [AC_DEFINE([WITH_SYNC_FETCH_AND_ADD_LONGLONG], [1], [use __sync_fetch_and_add]) AC_MSG_RESULT([yes])],
   [AC_MSG_RESULT([no])]
)

PKG_PROG_PKG_CONFIG

AC_ARG_WITH(ssl, AS_HELP_STRING([--with-ssl], [Use SSL/TLS with specified library. Options: 'gnutls' (default), 'openssl', 'wolfssl' or 'none']), with_ssl=$withval, with_ssl="yes")

AS_IF([test "$with_ssl" = "gnutls" || test "$with_ssl" = "yes"], [
  PKG_CHECK_MODULES([GNUTLS], [gnutls], [
    with_gnutls=yes
    LIBS="$GNUTLS_LIBS $LIBS"
    CFLAGS="$GNUTLS_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_GNUTLS], [1], [Use GnuTLS])
    AC_DEFINE([WITH_GNUTLS_IN_TESTSUITE], [1], [GnuTLS is available for test suite.])
    AC_SEARCH_LIBS(gnutls_hash, gnutls, [with_gnutls_hash=yes])
    AS_IF([test "$with_gnutls_hash" = "yes"],
      [AC_CHECK_HEADERS([gnutls/crypto.h], [], [], [#include <gnutls/gnutls.h>])])
    AC_CHECK_HEADERS([gnutls/ocsp.h],
      [AC_DEFINE([WITH_OCSP], [1], [OCSP is supported.])
       AC_DEFINE([WITH_GNUTLS_OCSP], [1], [GnuTLS OCSP is supported for test suite.])],
      [AC_MSG_WARN(*** Header file gnutls/ocsp.h was not found. OCSP will be disabled.)])
    AC_CHECK_FUNCS(gnutls_srp_server_get_username gnutls_transport_get_int)
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(gnutls_global_init, gnutls,
      [with_gnutls=yes],
      [AC_MSG_WARN(*** GNUTLS was not found. Fallback to libnettle for hashing and checksumming.)])
    GNUTLS_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])

AS_IF([test "$with_ssl" = "openssl" || (test "$with_ssl" = "yes" && test "$with_gnutls" != "yes")], [
  PKG_CHECK_MODULES([OPENSSL], [openssl], [
    with_openssl=yes
    LIBS="$OPENSSL_LIBS $LIBS"
    CFLAGS="$OPENSSL_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_OPENSSL], [1], [Use OpenSSL])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(SSL_CTX_new, ssl,
      [with_openssl=yes; AC_DEFINE([WITH_OPENSSL], [1], [Use OpenSSL])],
      [AC_MSG_WARN(*** OpenSSL was not found.)
    ])
    OPENSSL_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])

  AS_IF([test "$with_openssl" = "yes"], [
    AC_CHECK_HEADERS([openssl/ssl.h])
    AC_CHECK_HEADERS([openssl/x509_vfy.h])
    AC_CHECK_HEADERS([openssl/ocsp.h],
      [AC_DEFINE([WITH_OCSP], [1], [OCSP is supported])],
      [AC_MSG_WARN(*** Header file openssl/ocsp.h was not found. OCSP will be disabled.)])

    AC_CHECK_FUNCS(SSL_new X509_STORE_add_lookup)

    AC_SEARCH_LIBS(EVP_MD_CTX_new, crypto,
      [with_libcrypto=yes; AC_DEFINE([WITH_LIBCRYPTO], [1], [Use libcrypto])],
      [with_libcrypto=no; AC_MSG_WARN(*** LIBCRYPTO was not found. Fallback to libwolfcrypt for hashing and checksumming.)
    ])
  ])
])

AS_IF([test "$with_ssl" = "wolfssl" || (test "$with_ssl" = "yes" && test "$with_gnutls" != "yes" && test "$with_openssl" != "yes")], [
  PKG_CHECK_MODULES([WOLFSSL], [wolfssl], [
    with_wolfssl=yes
    LIBS="$WOLFSSL_LIBS $LIBS"
    CFLAGS="$WOLFSSL_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_WOLFSSL], [1], [Use WolfSSL])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(wolfSSL_Init, wolfssl,
      [with_wolfssl=yes; AC_DEFINE([WITH_WOLFSSL], [1], [Use WolfSSL])],
      [AC_MSG_WARN(*** WolfSSL was not found.)])
    WOLFSSL_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])

  AS_IF([test "$with_wolfssl" = "yes"], [
    with_libwolfcrypt=yes
    AC_DEFINE([WITH_LIBWOLFCRYPT], [1], [Use wolfcrypt])
  ])
])

AS_IF([test "$with_gnutls" = "yes" || test "$with_wolfssl" = "yes" || test "$with_openssl" = "yes"], [
  AC_DEFINE([WITH_TLS], [1], [Built with TLS support])
  AS_IF([test "$with_gnutls" = "yes"], [ssl_enabled="gnutls"],
        [test "$with_openssl" = "yes"], [ssl_enabled="openssl"],
        [test "$with_wolfssl" = "yes"], [ssl_enabled="wolfssl"],
        [ssl_enabled="(not found)"])
], [
  AS_IF([test "$with_ssl" != "none"], [
    AS_IF([test "$with_ssl" = "yes"], [AC_MSG_ERROR([*** No SSL/TLS library not found.])],
          [AC_MSG_ERROR([*** SSL/TLS library "$with_ssl" not found.])])
  ])
  ssl_enabled="none"
])

#AS_IF([test "$with_gnutls" != "yes" && test "$with_openssl" != "yes" && test "$with_wolfssl" != "yes"], [
#  AS_IF([test "$with_ssl" != "none"], [
#    AC_MSG_ERROR([*** Unsupported value for --with-ssl. Use 'gnutls' (default), 'openssl', 'wolfssl' or 'none'])
#  ])
#  ssl_enabled="(not found)"
#])

AM_CONDITIONAL([WITH_GNUTLS], [test "$with_gnutls" = "yes"])
AM_CONDITIONAL([WITH_OPENSSL], [test "$with_openssl" = "yes"])
AM_CONDITIONAL([WITH_WOLFSSL], [test "$with_wolfssl" = "yes"])

AM_CONDITIONAL([WITH_TLS], [test "$with_gnutls" = "yes" || test "$with_wolfssl" = "yes" || test "$with_openssl" = "yes"])

AS_IF([(test "$with_gnutls" != "yes" || test "$with_gnutls_hash" != "yes") && test "$with_libwolfcrypt" != "yes" && test "$with_libcrypto" != "yes"], [
  PKG_CHECK_MODULES([NETTLE], nettle, [
    with_libnettle=yes
    LIBS="$NETTLE_LIBS $LIBS"
    CFLAGS="$NETTLE_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBNETTLE], [1], [Use libnettle])
  ], [
     with_libnettle=no
     AC_MSG_WARN(*** LIBNETTLE was not found. Fallback to libgcrypt for hashing and checksumming.)
  ])

  AS_IF([test "$with_libnettle" != "yes"], [
    AC_SEARCH_LIBS(gcry_check_version, gcrypt,
      [with_gcrypt=yes; AC_DEFINE([WITH_GCRYPT], [1], [Use libgcrypt]) AC_CHECK_HEADERS([gcrypt.h])],
      [with_gcrypt=no;  AC_MSG_WARN(*** LIBGCRYPT was not found. Fallback to gnulib for hashing and checksumming.)])
  ])
])

AM_CONDITIONAL([WITH_LIBNETTLE], [test "$with_libnettle" = "yes"])
AM_CONDITIONAL([WITH_CRYPT], [test "$with_gcrypt" = "yes"])

AC_ARG_WITH(libpsl, AS_HELP_STRING([--without-libpsl], [disable support for libpsl cookie checking]), with_libpsl=$withval, with_libpsl=yes)
AS_IF([test "$with_libpsl" != "no"], [
  PKG_CHECK_MODULES([LIBPSL], libpsl, [
    with_libpsl=yes
    # correct $LIBPSL_LIBS (in libpsl <= 0.6.0)
    AS_IF([test "$LIBPSL_LIBS" = "-llibpsl "], [LIBPSL_LIBS="-lpsl"])
    LIBS="$LIBPSL_LIBS $LIBS"
    CFLAGS="$LIBPSL_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBPSL], [1], [PSL support enabled])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(psl_builtin, psl,
      [with_libpsl=yes; AC_DEFINE([WITH_LIBPSL], [1], [PSL support enabled])],
      [with_libpsl=no;  AC_MSG_WARN(*** libpsl was not found. Fallback to builtin cookie checking.)])
    LIBPSL_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_LIBPSL], [test "$with_libpsl" = "yes"])

AC_ARG_WITH(libhsts, AS_HELP_STRING([--without-libhsts], [disable support for libhsts checking]), with_libhsts=$withval, with_libhsts=yes)
AS_IF([test "$with_libhsts" != "no"], [
  PKG_CHECK_MODULES([LIBHSTS], libhsts, [
    with_libhsts=yes
    LIBS="$LIBHSTS_LIBS $LIBS"
    CFLAGS="$LIBHSTS_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBHSTS], [1], [HSTS Preload List support enabled])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(hsts_get_version, hsts,
      [with_libhsts=yes; AC_DEFINE([WITH_LIBHSTS], [1], [HSTS Preload List support enabled])],
      [with_libhsts=no;  AC_MSG_WARN(*** libhsts was not found.)])
    LIBHSTS_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_LIBHSTS], [test "$with_libHSTS" = "yes"])

AC_ARG_WITH(libnghttp2, AS_HELP_STRING([--without-libnghttp2], [disable support for libnghttp2]), with_libnghttp2=$withval, with_libnghttp2=yes)
AS_IF([test "$with_libnghttp2" != "no"], [
  PKG_CHECK_MODULES([LIBNGHTTP2], libnghttp2, [
    with_libnghttp2=yes
    LIBS="$LIBNGHTTP2_LIBS $LIBS"
    CFLAGS="$LIBNGHTTP2_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBNGHTTP2], [1], [HTTP/2.0 support enabled via libnghttp2])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(nghttp2_session_client_new, nghttp2,
      [with_libnghttp2=yes; AC_DEFINE([WITH_LIBNGHTTP2], [1], [HTTP/2.0 support enabled via libnghttp2])],
      [with_libnghttp2=no;  AC_MSG_WARN(*** libnghttp2 was not found. HTTP/2.0 support disabled.)])
    LIBNGHTTP2_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_LIBNGHTTP2], [test "$with_libnghttp2" = "yes"])

AC_ARG_WITH(gpgme, AS_HELP_STRING([--without-gpgme], [support signature verification with gpgme]), with_gpgme=$withval, with_gpgme=yes)
AS_IF([test "$with_gpgme" != "no"], [
  PKG_CHECK_MODULES([GPGME], gpgme, [
    with_gpgme=yes
    LIBS="$GPGME_LIBS $LIBS"
    CFLAGS="$GPGME_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_GPGME], [1], [Use gpgme])
  ], [
    m4_ifdef([AM_PATH_GPGME],[
      AM_PATH_GPGME([], [
        with_gpgme=yes
        LIBS="$GPGME_LIBS $LIBS"
        CFLAGS="$GPGME_CFLAGS $CFLAGS"
        AC_DEFINE([WITH_GPGME], [1], [Use gpgme])
      ],[
        with_gpgme=no; AC_MSG_WARN(*** GPGME not found.)
      ])
    ], [
      with_gpgme=no; AC_MSG_WARN(*** GPGME not found. Signature verification is not possible)
    ])
  ])
])
AM_CONDITIONAL([WITH_GPGME], [test "$with_gpgme" = "yes"])

AC_ARG_WITH(bzip2, AS_HELP_STRING([--with-bzip2], [enable bzip2 compression support]), with_bzip2=$withval, with_bzip2=no)
AS_IF([test "$with_bzip2" = "yes"], [
  OLD_LIBS="$LIBS"
  LIBS=
  AC_SEARCH_LIBS(BZ2_bzDecompress, bz2,
    [with_bzip2=yes; AC_DEFINE([WITH_BZIP2], [1], [Use libbz2])],
    [with_bzip2=no;  AC_MSG_WARN(*** libbz2 was not found. You will not be able to use BZIP2 (de)compression)])
  BZ2_LIBS="$LIBS"
  LIBS="$LIBS $OLD_LIBS"
])
AM_CONDITIONAL([WITH_BZIP2], [test "$with_bzip2" = "yes"])

AC_ARG_WITH(zlib, AS_HELP_STRING([--without-zlib], [disable gzip compression support]), with_zlib=$withval, with_zlib=yes)
AS_IF([test "$with_zlib" != "no"], [
  PKG_CHECK_MODULES([ZLIB], zlib, [
    with_zlib=yes
    LIBS="$ZLIB_LIBS $LIBS"
    CFLAGS="$ZLIB_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_ZLIB], [1], [Use zlib])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(deflate, z,
      [with_zlib=yes; AC_DEFINE([WITH_ZLIB], [1], [Use zlib])],
      [with_zlib=no;  AC_MSG_WARN(*** ZLIB was not found. You will not be able to use gzip (de)compression)])
    ZLIB_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_ZLIB], [test "$with_zlib" = "yes"])

AC_ARG_WITH(lzma, AS_HELP_STRING([--with-lzma], [enable LZMA compression support]), with_lzma=$withval, with_lzma=no)
AS_IF([test "$with_lzma" = "yes"], [
  PKG_CHECK_MODULES([LZMA], liblzma, [
    with_lzma=yes
    LIBS="$LZMA_LIBS $LIBS"
    CFLAGS="$LZMA_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LZMA], [1], [Use liblzma])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(lzma_code, lzma,
      [with_lzma=yes; AC_DEFINE([WITH_LZMA], [1], [Use liblzma])],
      [with_lzma=no;  AC_MSG_WARN(*** liblzma was not found. You will not be able to use LZMA (de)compression)])
    LZMA_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_LZMA], [test "$with_lzma" = "yes"])

AC_ARG_WITH(brotlidec, AS_HELP_STRING([--without-brotlidec], [disable Brotli compression support]), with_brotlidec=$withval, with_brotlidec=yes)
AS_IF([test "$with_brotlidec" != "no"], [
  PKG_CHECK_MODULES([BROTLIDEC], libbrotlidec, [
    with_brotlidec=yes
    LIBS="$BROTLIDEC_LIBS $LIBS"
    CFLAGS="$BROTLIDEC_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_BROTLIDEC], [1], [Use brotlidec])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(BrotliDecoderCreateInstance, brotlidec,
      [with_brotlidec=yes; AC_DEFINE([WITH_BROTLIDEC], [1], [Use libbrotlidec])],
      [with_brotlidec=no;  AC_MSG_WARN(*** libbrotlidec was not found. You will not be able to use Brotli decompression)])
    BROTLIDEC_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_BROTLIDEC], [test "$with_brotlidec" = "yes"])

AC_ARG_WITH(zstd, AS_HELP_STRING([--without-zstd], [disable Zstandard compression support]), with_zstd=$withval, with_zstd=yes)
AS_IF([test "$with_zstd" != "no"], [
  PKG_CHECK_MODULES([ZSTD], libzstd, [
    with_zstd=yes
    LIBS="$ZSTD_LIBS $LIBS"
    CFLAGS="$ZSTD_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_ZSTD], [1], [Use zstd])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(ZSTD_decompressStream, zstd,
      [with_zstd=yes; AC_DEFINE([WITH_ZSTD], [1], [Use libzstd])],
      [with_zstd=no;  AC_MSG_WARN(*** libzstd was not found. You will not be able to use Zstandard decompression)])
    ZSTD_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_ZSTD], [test "$with_zstd" = "yes"])

AC_ARG_WITH(lzip, AS_HELP_STRING([--without-lzip], [disable lzip compression support]), with_lzip=$withval, with_lzip=yes)
AS_IF([test "$with_lzip" != "no"], [
  PKG_CHECK_MODULES([LZIP], liblz, [
    with_lzip=yes
    LIBS="$LZIP_LIBS $LIBS"
    CFLAGS="$LZIP_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LZIP], [1], [Use liblz (lzip)])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(LZ_decompress_open, lz,
      [with_lzip=yes; AC_DEFINE([WITH_LZIP], [1], [Use liblz (lzip)])],
      [with_lzip=no;  AC_MSG_WARN(*** liblz was not found. You will not be able to use lzip decompression)])
    LZIP_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_LZIP], [test "$with_lzip" = "yes"])

# Support for internationalized domain names.
# IDN support in Wget2 is provided in multiple ways:
#   1. libidn2 >= 0.14.0 (IDNA 2008)
#   3. libidn (IDNA 2003)
#
# If libidn2 is not found at all, we try to fallback to libidn.
AC_ARG_WITH(libidn2, AS_HELP_STRING([--without-libidn2], [disable IDN2 support]), with_libidn2=$withval, with_libidn2=yes)
AS_IF([test "$with_libidn2" != "no"], [
  PKG_CHECK_MODULES([LIBIDN2], [libidn2 >= 0.14.0], [
    with_libidn2=yes
    IDNA_INFO="IDNA 2008 (libidn2)"
    LIBS="$LIBIDN2_LIBS $LIBS"
    CFLAGS="$LIBIDN2_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBIDN2], [1], [Use libidn2])
  ], [
    with_libidn2=no
    AC_MSG_WARN(*** LIBIDN2 was not found. You will not be able to use IDN2008 support)
    ])
])

AM_CONDITIONAL([WITH_LIBIDN2], [test "$with_libidn2" = "yes"])

AS_IF([test "$with_libidn2" != "yes"], [
  AC_ARG_WITH(libidn, AS_HELP_STRING([--without-libidn], [disable IDN support]), with_libidn=$withval, with_libidn=yes)
  AS_IF([test "$with_libidn" != "no"], [
    PKG_CHECK_MODULES([LIBIDN], libidn, [
      with_libidn=yes
      LIBS="$LIBIDN_LIBS $LIBS"
      CFLAGS="$LIBIDN_CFLAGS $CFLAGS"
      AC_DEFINE([WITH_LIBIDN], [1], [Use libidn])
      IDNA_INFO="IDNA 2003 (libidn)"
    ], [
      OLD_LIBS="$LIBS"
      LIBS=
      AC_SEARCH_LIBS(idna_to_ascii_8z, idn,
        [with_libidn=yes; AC_DEFINE([WITH_LIBIDN], [1], [Use libidn]) IDNA_INFO="IDNA 2003 (libidn)"],
        [with_libidn=no;  AC_MSG_WARN(*** LIBIDN was not found. You will not be able to use IDN support)])
      LIBIDN_LIBS="$LIBS"
      LIBS="$LIBS $OLD_LIBS"
    ])
  ])
])
AM_CONDITIONAL([WITH_LIBIDN], [test "$with_libidn" = "yes"])

AC_ARG_WITH(libpcre2, AS_HELP_STRING([--without-libpcre2], [disable support for libpcre2]), with_libpcre2=$withval, with_libpcre2=yes)
AS_IF([test "$with_libpcre2" != "no"], [
  PKG_CHECK_MODULES([LIBPCRE2], libpcre2-8, [
    with_libpcre2=yes
    LIBS="$LIBPCRE2_LIBS $LIBS"
    CFLAGS="$LIBPCRE2_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBPCRE2], [1], [PCRE regex support enabled via libpcre2])
  ], [
    OLD_LIBS="$LIBS"
    LIBS=
    AC_SEARCH_LIBS(pcre2_compile_8, pcre2-8,
      [with_libpcre2=yes; AC_DEFINE([WITH_LIBPCRE2], [1], [PCRE regex support enabled via libpcre2])],
      [with_libpcre2=no;  AC_MSG_WARN(*** libpcre2 was not found. PCRE2 regex support disabled.)])
    LIBPCRE2_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
  ])
])
AM_CONDITIONAL([WITH_LIBPCRE2], [test "$with_libpcre2" = "yes"])

AS_IF([test "$with_libpcre2" != "yes"], [
 AC_ARG_WITH(libpcre, AS_HELP_STRING([--without-libpcre], [disable support for libpcre]), with_libpcre=$withval, with_libpcre=yes)
 AS_IF([test "$with_libpcre" != "no"], [
   PKG_CHECK_MODULES([LIBPCRE], libpcre, [
     with_libpcre=yes
     LIBS="$LIBPCRE_LIBS $LIBS"
     CFLAGS="$LIBPCRE_CFLAGS $CFLAGS"
     AC_DEFINE([WITH_LIBPCRE], [1], [PCRE regex support enabled via libpcre])
   ], [
    OLD_LIBS="$LIBS"
    LIBS=
     AC_SEARCH_LIBS(pcre_compile, pcre,
       [with_libpcre=yes; AC_DEFINE([WITH_LIBPCRE], [1], [PCRE regex support enabled via libpcre])],
       [with_libpcre=no;  AC_MSG_WARN(*** libpcre was not found. PCRE regex support disabled.)])
    LIBPCRE_LIBS="$LIBS"
    LIBS="$LIBS $OLD_LIBS"
   ])
 ])
])
AM_CONDITIONAL([WITH_LIBPCRE], [test "$with_libpcre" = "yes"])

AS_IF([test "$with_libpcre" = "yes"], [HAVE_PCRE="yes, via libpcre"], [test "$with_libpcre2" = "yes"], [HAVE_PCRE="yes, via libpcre2"], [HAVE_PCRE=no])

AC_ARG_WITH(libmicrohttpd, AS_HELP_STRING([--without-libmicrohttpd], [disable support for libmicrohttpd]), with_libmicrohttpd=$withval, with_libmicrohttpd=yes)
AS_IF([test "$with_libmicrohttpd" != "no"], [
  old_LIBS=$LIBS
  old_CFLAGS=$CFLAGS
  PKG_CHECK_MODULES(MICROHTTPD, [libmicrohttpd], [
    with_libmicrohttpd=yes
    TEST_LIBS="$MICROHTTPD_LIBS $TEST_LIBS"
    TEST_CFLAGS="$MICROHTTPD_CFLAGS $TEST_CFLAGS"
    AC_DEFINE([WITH_MICROHTTPD], [1], [Use Libmicrohttpd])
    LIBS="$MICROHTTPD_LIBS $LIBS"
    CFLAGS="$MICROHTTPD_CFLAGS $CFLAGS"
    AC_CHECK_FUNCS(MHD_free)
    AC_CHECK_HEADERS([microhttpd_http2.h])
    LIBS=$old_LIBS
    CFLAGS=$old_CFLAGS
  ], [
    AC_SEARCH_LIBS(MHD_start_daemon, microhttpd,
      [with_libmicrohttpd=yes; AC_DEFINE([WITH_MICROHTTPD], [1], [Use libmicrohttpd])],
      [with_libmicrohttpd=no; AC_MSG_WARN(*** LIBMICROHTTPD was not found. Several tests will not run.)])
    AC_CHECK_FUNCS(MHD_free)
    AC_CHECK_HEADERS([microhttpd_http2.h])
    TEST_LIBS=$LIBS
    TEST_CFLAGS=$CFLAGS
  ])
  LIBS=$old_LIBS
  CFLAGS=$old_CFLAGS

  AS_IF([test "$with_libmicrohttpd" = "yes" && test "$with_gnutls" != "yes"], [
    dnl MHD needs GnuTLS
    PKG_CHECK_MODULES([GNUTLS], [gnutls], [
      TEST_LIBS="$TEST_LIBS $GNUTLS_LIBS"
      TEST_CFLAGS="$TEST_CFLAGS $GNUTLS_CFLAGS"
      AC_DEFINE([WITH_GNUTLS_IN_TESTSUITE], [1], [GnuTLS is available for test suite.])
      AC_CHECK_HEADERS([gnutls/ocsp.h],
        [AC_DEFINE([WITH_GNUTLS_OCSP], [1], [GnuTLS OCSP is supported for test suite.])],
        [AC_MSG_WARN(*** Header file gnutls/ocsp.h was not found. OCSP will be disabled for tests.)])
    ], [
      old_LIBS=$LIBS
      old_CFLAGS=$CFLAGS
      AC_SEARCH_LIBS(gnutls_global_init, gnutls,
        [AC_DEFINE([WITH_GNUTLS_IN_TESTSUITE], [1], [GnuTLS is available for test suite.])],
        [AC_MSG_WARN(*** GnuTLS is not available. Some tests will not run.)])
      TEST_LIBS=$LIBS
      TEST_CFLAGS=$CFLAGS
      LIBS=$old_LIBS
      CFLAGS=$old_CFLAGS
    ])
  ])
])

AM_CONDITIONAL([WITH_MICROHTTPD], [test "$with_libmicrohttpd" = "yes"])

# Check for plugin support
AC_CANONICAL_HOST
case "$host_os" in
	mingw*)
		dl_impl="windows";
		;;
	win32*)
		dl_impl="windows";
		;;
	*)
		dl_impl="libdl";
		;;
esac
AC_ARG_WITH(plugin_support,
	AS_HELP_STRING([--without-plugin-support],
		[Disable plugin support]),
		[plugin_support="$withval"],
		[plugin_support="yes"])
FUZZ_LIBS=$LIBS
if test "$plugin_support" = "no"; then
	OLD_LIBS=$LIBS
	AC_SEARCH_LIBS([dlsym], [dl dld])
	FUZZ_LIBS=$LIBS
	LIBS=$OLD_LIBS
elif test "$dl_impl" = "libdl"; then
	AC_SEARCH_LIBS([dlsym], [dl ldl], [:], [dl_impl="none"])
	FUZZ_LIBS=$LIBS
fi
AC_SUBST([FUZZ_LIBS])
if test "$plugin_support" = "yes" && test "$dl_impl" = "none"; then
	AC_MSG_WARN(*** No working backend for plugin support found)
	plugin_support="no"
fi
if test "$plugin_support" = "yes"; then
	AC_DEFINE([PLUGIN_SUPPORT], [1], [Enable plugin support])
	if test "$dl_impl" = "windows"; then
		AC_DEFINE([PLUGIN_SUPPORT_WINDOWS], [1], [Use windows API for plugins])
	else
		AC_DEFINE([PLUGIN_SUPPORT_LIBDL], [1], [Use libdl for plugins])
	fi
fi
AM_CONDITIONAL([PLUGIN_SUPPORT], [test "$plugin_support" = "yes"])

AC_SUBST([TEST_CFLAGS])
AC_SUBST([TEST_LIBS])
AC_SUBST([ALL_LIBS], $LIBS)

# Checks for header files.
AC_CHECK_HEADERS([\
 crypt.h idna.h idn/idna.h idn2.h unicase.h netinet/tcp.h])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([\
 strlcpy getuid fmemopen])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 include/Makefile
                 include/wget/Makefile
                 libwget/Makefile
                 src/Makefile
                 examples/Makefile
                 unit-tests/Makefile
                 tests/Makefile
                 fuzz/Makefile
                 libwget.pc
                 docs/Makefile
                 docs/libwget.doxy
                 docs/wget2_md2man.sh])
AC_OUTPUT

AC_MSG_NOTICE([Summary of build options:

  Version:            ${PACKAGE_VERSION}
  Host OS:            ${host_os}
  Install prefix:     ${prefix}
  Compiler:           ${CC}
  CFlags:             ${CFLAGS} ${CPPFLAGS} ${WARN_CFLAGS}
  LDFlags:            ${LDFLAGS}
  Libs:               ${LIBS}
  Library types:      shared=${enable_shared}, static=${enable_static}
  Small libraries:    $enable_manylibs
  SSL/TLS support:    $ssl_enabled
  GZIP compression:   $with_zlib
  BZIP2 compression:  $with_bzip2
  LZMA compression:   $with_lzma
  Brotli compression: $with_brotlidec
  Zstd compression:   $with_zstd
  Lzip compression:   $with_lzip
  IDNA support:       $IDNA_INFO
  PSL support:        $with_libpsl
  HSTS support:       $with_libhsts
  HTTP/2.0 support:   $with_libnghttp2
  Documentation:      $DOCS_INFO
  Wget2 docs:         $WGET2_DOCS_INFO
  Libwget docs:       $LIBWGET_DOCS_INFO
  PCRE support:       ${HAVE_PCRE}
  Tests:              ${TESTS_INFO}
  Assertions:         $ENABLE_ASSERT
  POSIX xattr:        $ENABLE_XATTR
  Microhttpd support: $with_libmicrohttpd (CFLAGS: ${TEST_CFLAGS}. LIBS: ${TEST_LIBS})
  Fuzzing build:      $enable_fuzzing, $LIB_FUZZING_ENGINE
  GPGME:              $with_gpgme
])

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
CFLAGS=$CFLAGS
LDFLAGS=$LDFLAGS

AC_PREREQ([2.67])
AC_INIT([wget2], [1.99.2], [bug-wget@gnu.org], [wget2], [https://savannah.gnu.org/projects/wget])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([subdir-objects parallel-tests gnu -Wno-portability dist-lzip])

CFLAGS=$CFLAGS
AC_USE_SYSTEM_EXTENSIONS
AC_GNU_SOURCE

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
if test "$EXTRA_CFLAGS" != ""; then
  CFLAGS="$CFLAGS $EXTRA_CFLAGS"
fi
if test "$XTRA_CFLAGS" != ""; then
  CFLAGS="$CFLAGS $XTRA_CFLAGS"
fi

# If CFLAGS isn't defined and using gcc, set CFLAGS to something reasonable.
# Otherwise, just prevent autoconf from molesting CFLAGS.
#AC_PROG_CC
AC_PROG_CC_STDC

#
# Require C99 support
#
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = "no"; then
  AC_ERROR([Compiler does not support C99. Aborting.])
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
AC_SUBST([LIBWGET_SO_VERSION], [0:0:0])
AC_SUBST([LIBWGET_VERSION], [0.0.1])

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
AC_CONFIG_MACRO_DIR([m4])

# Non-verbose make
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Check for large file support.  This check needs to come fairly
# early because it could (in principle) affect whether functions and
# headers are available, whether they work, etc.
AC_SYS_LARGEFILE
AC_CHECK_SIZEOF(off_t)

# Checks for programs.

#AM_NLS
#IT_PROG_INTLTOOL([0.40.0])
AC_PROG_LEX
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_CC_C_O

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

AC_ARG_ENABLE([fuzzing],
  [AS_HELP_STRING([--enable-fuzzing], [Turn on fuzzing build (for developers)])],
  [enable_fuzzing=yes; AC_SUBST([LIB_FUZZING_ENGINE])], [enable_fuzzing=no; LIB_FUZZING_ENGINE=""])
AM_CONDITIONAL([FUZZING], [test ! -z "$LIB_FUZZING_ENGINE"])

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
  gl_WARN_ADD([-fno-sanitize-recover=undefined])

  # additional clang options
  gl_WARN_ADD([-fsanitize=integer])
  gl_WARN_ADD([-fsanitize=nullability])
  gl_WARN_ADD([-fno-sanitize-recover=integer])
  gl_WARN_ADD([-fno-sanitize-recover=nullability])
fi

if test "$gl_cc_sanitize_asan" = yes; then
  gl_WARN_ADD([-fsanitize=address])
  gl_WARN_ADD([-fno-omit-frame-pointer])

  # additional clang option
  gl_WARN_ADD([-fsanitize-address-use-after-scope])
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
  [ENABLE_XATTR=$enableval],
  [ENABLE_XATTR=yes])

case "$host_os" in
  *linux* | *darwin*) xattr_syscalls="fsetxattr" ;;
  freebsd*)           xattr_syscalls="extattr_set_fd" ;;
  *)  AC_MSG_NOTICE([Disabling Extended Attribute support: your system is not known to support extended attributes.])
      ENABLE_XATTR=no
esac

if test "X${ENABLE_XATTR}" = "Xyes"; then
  AC_CHECK_FUNCS([$xattr_syscalls], [], [
    AC_MSG_NOTICE([Disabling Extended Attribute support: your system does not support $xattr_syscalls])
    ENABLE_XATTR=no
  ])
fi

test "X${ENABLE_XATTR}" = "Xyes" && AC_DEFINE([ENABLE_XATTR], 1,
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
AM_CONDITIONAL([HAVE_PO], [ test "$have_po" = yes ])

#
# check for doxygen and pandoc
#
AC_ARG_ENABLE(doc, AS_HELP_STRING([--disable-doc], [don t generate any documentation]),
  enable_doc=$enableval, enable_doc=yes)
if test "$enable_doc" = yes; then
  AC_CHECK_PROGS([DOXYGEN], [doxygen])
  AC_CHECK_PROGS([PANDOC], [pandoc])

  if test -n "$DOXYGEN" || test -n "$PANDOC"; then
    LIBWGET_DOCS_INFO="yes (found:"
    if test -n "$DOXYGEN"; then
      LIBWGET_DOCS_INFO+=" Doxygen)"
	else
	  LIBWGET_DOCS_INFO="no"
    fi
    WGET2_DOCS_INFO="yes (found:"
    if test -n "$PANDOC"; then
      WGET2_DOCS_INFO+=" Pandoc)"
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
#AC_ARG_ENABLE(man,[AC_HELP_STRING([--enable-man],
#                                  [generate man pages [default=auto]])],enable_man=yes,enable_man=no)

#AM_CONDITIONAL(ENABLE_MAN, test x$enable_man != xno)
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
AS_IF([test "x${ac_enable_valgrind}" != xno], [
  AC_CHECK_PROG(HAVE_VALGRIND, valgrind, yes, no)
  AS_IF([test "x$HAVE_VALGRIND" = xyes], [
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

AC_ARG_WITH(ssl, AS_HELP_STRING([--with-ssl], [Use SSL/TLS with specified library. Options: 'gnutls' (default), 'openssl', 'wolfssl' or 'none']), with_ssl=$withval, with_ssl=gnutls)

AS_IF([test "x$with_ssl" == "xgnutls"], [
  PKG_CHECK_MODULES([GNUTLS], [gnutls], [
    with_gnutls=yes
    LIBS="$GNUTLS_LIBS $LIBS"
    CFLAGS="$GNUTLS_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_GNUTLS], [1], [Use GnuTLS])
  ], [
    AC_SEARCH_LIBS(gnutls_global_init, gnutls,
      [with_gnutls=yes; AC_DEFINE([WITH_GNUTLS], [1], [Use GnuTLS])],
      [with_gnutls=no;  AC_MSG_WARN(*** GNUTLS was not found. You will not be able to use HTTPS. Fallback to libnettle for hashing and checksumming.)])
  ])

  AS_IF([test "x$with_gnutls" == xyes], [
    AC_SEARCH_LIBS(gnutls_hash, gnutls, [with_gnutls_hash=yes])
    AS_IF([test "x$with_gnutls_hash" == xyes],
      [AC_CHECK_HEADERS([gnutls/crypto.h], [], [], [#include <gnutls/gnutls.h>])])
    AC_CHECK_HEADERS([gnutls/ocsp.h])
    AC_CHECK_FUNCS(gnutls_srp_server_get_username gnutls_transport_get_int)
  ])
])

AS_IF([test "x$with_ssl" == "xopenssl"], [
  PKG_CHECK_MODULES([OPENSSL], [openssl], [
    with_openssl=yes
    LIBS="$OPENSSL_LIBS $LIBS"
    CFLAGS="$OPENSSL_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_OPENSSL], [1], [Use OpenSSL])
  ], [
    AC_SEARCH_LIBS(SSL_CTX_new, openssl,
      [with_openssl=yes; AC_DEFINE([WITH_OPENSSL], [1], [Use OpenSSL])],
      [with_openssl=no;  AC_MSG_WARN(*** OpenSSL was not found.)
    ])
  ])

  AS_IF([test "x$with_openssl" == xyes], [
    AC_CHECK_HEADERS([openssl/ssl.h])
    AC_CHECK_HEADERS([openssl/x509_vfy.h])
    AC_CHECK_FUNCS(SSL_new X509_STORE_add_lookup)

    AC_SEARCH_LIBS(EVP_MD_CTX_new, crypto,
      [with_libcrypto=yes; AC_DEFINE([WITH_LIBCRYPTO], [1], [Use libcrypto])],
      [with_libcrypto=no; AC_MSG_WARN(*** LIBCRYPTO was not found. Fallback to libwolfcrypt for hashing and checksumming.)
    ])
  ])
])

AS_IF([test "x$with_ssl" = "xwolfssl"], [
  PKG_CHECK_MODULES([WOLFSSL], [wolfssl], [
    with_wolfssl=yes
    LIBS="$WOLFSSL_LIBS $LIBS"
    CFLAGS="$WOLFSSL_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_WOLFSSL], [1], [Use WolfSSL])
  ], [
    AC_SEARCH_LIBS(wolfSSL_Init, wolfssl,
      [with_wolfssl=yes; AC_DEFINE([WITH_WOLFSSL], [1], [Use WolfSSL])],
      [with_wolfssl=no;  AC_MSG_WARN(*** WolfSSL was not found. You will not be able to use HTTPS.)])
  ])

  AS_IF([test "x$with_wolfssl" = xyes], [
    with_libwolfcrypt=yes
    AC_DEFINE([WITH_LIBWOLFCRYPT], [1], [Use wolfcrypt])
  ])
])

AM_CONDITIONAL([WITH_GNUTLS], [test "x$with_gnutls" = xyes])
AM_CONDITIONAL([WITH_OPENSSL], [test "x$with_openssl" = xyes])
AM_CONDITIONAL([WITH_WOLFSSL], [test "x$with_wolfssl" = xyes])

AM_CONDITIONAL([WITH_TLS], [test "x$with_gnutls" = xyes || test "x$with_wolfssl" = xyes || test "x$with_openssl" = xyes])
AS_IF([test "x$with_gnutls" = xyes || test "x$with_wolfssl" = xyes || test "x$with_openssl" = xyes], [
  AC_DEFINE([WITH_TLS], [1], [Built with TLS support])
], [AC_DEFINE([WITH_TLS], [0], [No TLS support])])

AS_IF([(test "x$with_gnutls" != xyes || test "x$with_gnutls_hash" != xyes) && test "x$with_libwolfcrypt" != xyes && test "x$with_libcrypto" != xyes], [
  PKG_CHECK_MODULES([NETTLE], nettle, [
    with_libnettle=yes
    LIBS="$NETTLE_LIBS $LIBS"
    CFLAGS="$NETTLE_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBNETTLE], [1], [Use libnettle])
  ], [
     with_libnettle=no
     AC_MSG_WARN(*** LIBNETTLE was not found. Fallback to libgcrypt for hashing and checksumming.)
  ])

  AS_IF([test "x$with_libnettle" != xyes], [
    AC_SEARCH_LIBS(gcry_check_version, gcrypt,
      [with_gcrypt=yes; AC_DEFINE([WITH_GCRYPT], [1], [Use libgcrypt]) AC_CHECK_HEADERS([gcrypt.h])],
      [with_gcrypt=no;  AC_MSG_WARN(*** LIBGCRYPT was not found. Fallback to gnulib for hashing and checksumming.)])
  ])
])

AM_CONDITIONAL([WITH_LIBNETTLE], [test "x$with_libnettle" = xyes])
AM_CONDITIONAL([WITH_CRYPT], [test "x$with_gcrypt" = xyes])

AC_ARG_WITH(libpsl, AS_HELP_STRING([--without-libpsl], [disable support for libpsl cookie checking]), with_libpsl=$withval, with_libpsl=yes)
AS_IF([test "x$with_libpsl" != xno], [
  PKG_CHECK_MODULES([LIBPSL], libpsl, [
    with_libpsl=yes
    # correct $LIBPSL_LIBS (in libpsl <= 0.6.0)
    AS_IF([test "x$LIBPSL_LIBS" = "x-llibpsl "], [LIBPSL_LIBS="-lpsl"])
    LIBS="$LIBPSL_LIBS $LIBS"
    CFLAGS="$LIBPSL_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBPSL], [1], [PSL support enabled])
  ], [
    AC_SEARCH_LIBS(psl_builtin, psl,
      [with_libpsl=yes; AC_DEFINE([WITH_LIBPSL], [1], [PSL support enabled])],
      [with_libpsl=no;  AC_MSG_WARN(*** libpsl was not found. Fallback to builtin cookie checking.)])
  ])
])
AM_CONDITIONAL([WITH_LIBPSL], [test "x$with_libpsl" = xyes])

AC_ARG_WITH(libhsts, AS_HELP_STRING([--without-libhsts], [disable support for libhsts checking]), with_libhsts=$withval, with_libhsts=yes)
AS_IF([test "x$with_libhsts" != xno], [
  PKG_CHECK_MODULES([LIBHSTS], libhsts, [
    with_libhsts=yes
    LIBS="$LIBHSTS_LIBS $LIBS"
    CFLAGS="$LIBHSTS_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBHSTS], [1], [HSTS Preload List support enabled])
  ], [
    AC_SEARCH_LIBS(hsts_get_version, hsts,
      [with_libhsts=yes; AC_DEFINE([WITH_LIBHSTS], [1], [HSTS Preload List support enabled])],
      [with_libhsts=no;  AC_MSG_WARN(*** libhsts was not found.)])
  ])
])
AM_CONDITIONAL([WITH_LIBHSTS], [test "x$with_libHSTS" = xyes])

AC_ARG_WITH(libnghttp2, AS_HELP_STRING([--without-libnghttp2], [disable support for libnghttp2]), with_libnghttp2=$withval, with_libnghttp2=yes)
AS_IF([test "x$with_libnghttp2" != xno], [
  PKG_CHECK_MODULES([LIBNGHTTP2], libnghttp2, [
    with_libnghttp2=yes
    LIBS="$LIBNGHTTP2_LIBS $LIBS"
    CFLAGS="$LIBNGHTTP2_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBNGHTTP2], [1], [HTTP/2.0 support enabled via libnghttp2])
  ], [
    AC_SEARCH_LIBS(nghttp2_session_client_new, nghttp2,
      [with_libnghttp2=yes; AC_DEFINE([WITH_LIBNGHTTP2], [1], [HTTP/2.0 support enabled via libnghttp2])],
      [with_libnghttp2=no;  AC_MSG_WARN(*** libnghttp2 was not found. HTTP/2.0 support disabled.)])
  ])
])
AM_CONDITIONAL([WITH_LIBNGHTTP2], [test "x$with_libnghttp2" = xyes])

AC_ARG_WITH(bzip2, AS_HELP_STRING([--without-bzip2], [disable bzip2 compression support]), with_bzip2=$withval, with_bzip2=yes)
AS_IF([test "x$with_bzip2" != xno], [
  AC_SEARCH_LIBS(BZ2_bzDecompress, bz2,
    [with_bzip2=yes; AC_SUBST([BZ2_LIBS], -lbz2) AC_DEFINE([WITH_BZIP2], [1], [Use libbz2])],
    [with_bzip2=no;  AC_MSG_WARN(*** libbz2 was not found. You will not be able to use BZIP2 (de)compression)])
])
AM_CONDITIONAL([WITH_BZIP2], [test "x$with_bzip2" = xyes])

AC_ARG_WITH(gpgme, AS_HELP_STRING([--without-gpgme], [support signature verification with gpgme]), with_gpgme=$withval, with_gpgme=yes)
AS_IF([test "x$with_gpgme" != xno], [
  m4_ifdef([AM_PATH_GPGME],[
	AM_PATH_GPGME([], [
	  with_gpgme=yes
	  LIBS="$GPGME_LIBS $LIBS"
	  CFLAGS="$GPGME_CFLAGS $CFLAGS"
	  AC_DEFINE([WITH_GPGME], [1], [Use gpgme])
	  ],[
		 with_gpgme=no; AC_MSG_WARN(*** GPGME not found.)
	  ])
	],
	[with_gpgme=no; AC_MSG_WARN(*** GPGME not found. Signature verification is not possible)])
])
AM_CONDITIONAL([WITH_GPGME], [test "x$with_gpgme" = xyes])

AC_ARG_WITH(zlib, AS_HELP_STRING([--without-zlib], [disable gzip compression support]), with_zlib=$withval, with_zlib=yes)
AS_IF([test "x$with_zlib" != xno], [
  PKG_CHECK_MODULES([ZLIB], zlib, [
    with_zlib=yes
    LIBS="$ZLIB_LIBS $LIBS"
    CFLAGS="$ZLIB_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_ZLIB], [1], [Use zlib])
  ], [
    AC_SEARCH_LIBS(deflate, z,
      [with_zlib=yes; AC_DEFINE([WITH_ZLIB], [1], [Use zlib])],
      [with_zlib=no;  AC_MSG_WARN(*** ZLIB was not found. You will not be able to use gzip (de)compression)])
  ])
])
AM_CONDITIONAL([WITH_ZLIB], [test "x$with_zlib" = xyes])

AC_ARG_WITH(lzma, AS_HELP_STRING([--without-lzma], [disable LZMA compression support]), with_lzma=$withval, with_lzma=yes)
AS_IF([test "x$with_lzma" != xno], [
  PKG_CHECK_MODULES([LZMA], liblzma, [
    with_lzma=yes
    LIBS="$LZMA_LIBS $LIBS"
    CFLAGS="$LZMA_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LZMA], [1], [Use liblzma])
  ], [
    AC_SEARCH_LIBS(lzma_code, lzma,
      [with_lzma=yes; AC_DEFINE([WITH_LZMA], [1], [Use liblzma])],
      [with_lzma=no;  AC_MSG_WARN(*** liblzma was not found. You will not be able to use LZMA (de)compression)])
  ])
])
AM_CONDITIONAL([WITH_LZMA], [test "x$with_lzma" = xyes])

AC_ARG_WITH(brotlidec, AS_HELP_STRING([--without-brotlidec], [disable Brotli compression support]), with_brotlidec=$withval, with_brotlidec=yes)
AS_IF([test "x$with_brotlidec" != xno], [
  PKG_CHECK_MODULES([BROTLIDEC], libbrotlidec, [
    with_brotlidec=yes
    LIBS="$BROTLIDEC_LIBS $LIBS"
    CFLAGS="$BROTLIDEC_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_BROTLIDEC], [1], [Use brotlidec])
  ], [
    AC_SEARCH_LIBS(BrotliDecoderCreateInstance, brotlidec,
      [with_brotlidec=yes; AC_DEFINE([WITH_BROTLIDEC], [1], [Use libbrotlidec])],
      [with_brotlidec=no;  AC_MSG_WARN(*** libbrotlidec was not found. You will not be able to use Brotli decompression)])
  ])
])
AM_CONDITIONAL([WITH_BROTLIDEC], [test "x$with_brotlidec" = xyes])

AC_ARG_WITH(zstd, AS_HELP_STRING([--without-zstd], [disable Zstandard compression support]), with_zstd=$withval, with_zstd=yes)
AS_IF([test "x$with_zstd" != xno], [
  PKG_CHECK_MODULES([ZSTD], libzstd, [
    with_zstd=yes
    LIBS="$ZSTD_LIBS $LIBS"
    CFLAGS="$ZSTD_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_ZSTD], [1], [Use zstd])
  ], [
    AC_SEARCH_LIBS(ZSTD_decompressStream, zstd,
      [with_zstd=yes; AC_DEFINE([WITH_ZSTD], [1], [Use libzstd])],
      [with_zstd=no;  AC_MSG_WARN(*** libzstd was not found. You will not be able to use Zstandard decompression)])
  ])
])
AM_CONDITIONAL([WITH_ZSTD], [test "x$with_zstd" = xyes])

# Support for internationalized domain names.
# IDN support in Wget2 is provided in multiple ways:
#   1. libidn2 >= 0.14.0 (IDNA 2008)
#   3. libidn (IDNA 2003)
#
# If libidn2 is not found at all, we try to fallback to libidn.
AC_ARG_WITH(libidn2, AS_HELP_STRING([--without-libidn2], [disable IDN2 support]), with_libidn2=$withval, with_libidn2=yes)
AS_IF([test "x$with_libidn2" != xno], [
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

AM_CONDITIONAL([WITH_LIBIDN2], [test "x$with_libidn2" = xyes])

AS_IF([test "x$with_libidn2" != xyes], [
  AC_ARG_WITH(libidn, AS_HELP_STRING([--without-libidn], [disable IDN support]), with_libidn=$withval, with_libidn=yes)
  AS_IF([test "x$with_libidn" != xno], [
    PKG_CHECK_MODULES([LIBIDN], libidn, [
      with_libidn=yes
      LIBS="$LIBIDN_LIBS $LIBS"
      CFLAGS="$LIBIDN_CFLAGS $CFLAGS"
      AC_DEFINE([WITH_LIBIDN], [1], [Use libidn])
      IDNA_INFO="IDNA 2003 (libidn)"
    ], [
      AC_SEARCH_LIBS(idna_to_ascii_8z, idn,
        [with_libidn=yes; AC_DEFINE([WITH_LIBIDN], [1], [Use libidn]) IDNA_INFO="IDNA 2003 (libidn)"],
        [with_libidn=no; AC_MSG_WARN(*** LIBIDN was not found. You will not be able to use IDN support)])
    ])
  ])
])
AM_CONDITIONAL([WITH_LIBIDN], [test "x$with_libidn" = xyes])

AC_ARG_WITH(libpcre2, AS_HELP_STRING([--without-libpcre2], [disable support for libpcre2]), with_libpcre2=$withval, with_libpcre2=yes)
AS_IF([test "x$with_libpcre2" != xno], [
  PKG_CHECK_MODULES([LIBPCRE2], libpcre2-8, [
    with_libpcre2=yes
    LIBS="$LIBPCRE2_LIBS $LIBS"
    CFLAGS="$LIBPCRE2_CFLAGS $CFLAGS"
    AC_DEFINE([WITH_LIBPCRE2], [1], [PCRE regex support enabled via libpcre2])
  ], [
    AC_SEARCH_LIBS(pcre2_compile_8, pcre2-8,
      [with_libpcre2=yes; AC_DEFINE([WITH_LIBPCRE2], [1], [PCRE regex support enabled via libpcre2])],
      [with_libpcre2=no; AC_MSG_WARN(*** libpcre2 was not found. PCRE2 regex support disabled.)])
  ])
])
AM_CONDITIONAL([WITH_LIBPCRE2], [test "x$with_libpcre2" = xyes])

AS_IF([test "x$with_libpcre2" != xyes], [
 AC_ARG_WITH(libpcre, AS_HELP_STRING([--without-libpcre], [disable support for libpcre]), with_libpcre=$withval, with_libpcre=yes)
 AS_IF([test "x$with_libpcre" != xno], [
   PKG_CHECK_MODULES([LIBPCRE], libpcre, [
     with_libpcre=yes
     LIBS="$LIBPCRE_LIBS $LIBS"
     CFLAGS="$LIBPCRE_CFLAGS $CFLAGS"
     AC_DEFINE([WITH_LIBPCRE], [1], [PCRE regex support enabled via libpcre])
   ], [
     AC_SEARCH_LIBS(pcre_compile, pcre,
       [with_libpcre=yes; AC_DEFINE([WITH_LIBPCRE], [1], [PCRE regex support enabled via libpcre])],
       [with_libpcre=no; AC_MSG_WARN(*** libpcre was not found. PCRE regex support disabled.)])
   ])
 ])
])
AM_CONDITIONAL([WITH_LIBPCRE], [test "x$with_libpcre" = xyes])

AS_IF([test "x$with_libpcre" = xyes], [HAVE_PCRE="yes, via libpcre"], [test "x$with_libpcre2" = xyes], [HAVE_PCRE="yes, via libpcre2"], [HAVE_PCRE=no])

AC_ARG_WITH(libmicrohttpd, AS_HELP_STRING([--without-libmicrohttpd], [disable support for libmicrohttpd]), with_libmicrohttpd=$withval, with_libmicrohttpd=yes)
AS_IF([test "x$with_libmicrohttpd" != xno], [
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
])
AM_CONDITIONAL([WITH_MICROHTTPD], [test "x$with_libmicrohttpd" = xyes])

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
if test "x$plugin_support" = "xno"; then
	OLD_LIBS=$LIBS
	AC_SEARCH_LIBS([dlsym], [dl dld])
	FUZZ_LIBS=$LIBS
	LIBS=$OLD_LIBS
elif test "x$dl_impl" = "xlibdl"; then
	AC_SEARCH_LIBS([dlsym], [dl ldl], [:], [dl_impl="none"])
	FUZZ_LIBS=$LIBS
fi
AC_SUBST([FUZZ_LIBS])
if test "x$plugin_support" = "xyes" && test "x$dl_impl" = "xnone"; then
	AC_MSG_WARN(*** No working backend for plugin support found)
	plugin_support="no"
fi
if test "x$plugin_support" = "xyes"; then
	AC_DEFINE([PLUGIN_SUPPORT], [1], [Enable plugin support])
	if test "x$dl_impl" = "xwindows"; then
		AC_DEFINE([PLUGIN_SUPPORT_WINDOWS], [1], [Use windows API for plugins])
	else
		AC_DEFINE([PLUGIN_SUPPORT_LIBDL], [1], [Use libdl for plugins])
	fi
fi
AM_CONDITIONAL([PLUGIN_SUPPORT], [test "x$plugin_support" = xyes])

AC_SUBST([TEST_CFLAGS])
AC_SUBST([TEST_LIBS])

# Checks for header files.
AC_CHECK_HEADERS([\
 crypt.h idna.h idn/idna.h idn2.h unicase.h netinet/tcp.h])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([\
 strlcpy getuid fmemopen])

# needed for src/version-text.h
YEAR=`date +%Y`
AC_SUBST([YEAR], $YEAR)

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 include/Makefile
                 include/wget/Makefile
                 libwget/Makefile
                 src/Makefile
                 src/version-text.h
                 examples/Makefile
                 unit-tests/Makefile
                 tests/Makefile
                 fuzz/Makefile
                 libwget.pc
                 docs/Makefile
                 docs/libwget.doxy
                 docs/wget2_md2man.sh])
AC_OUTPUT

# Check if expected TLS library was found and print it
AS_IF([test "x$with_ssl" == xwolfssl && test "x$with_wolfssl" == xno], [ssl_enabled="(not found)"],
  [test "x$with_ssl" == xopenssl && test "x$with_openssl" == xno], [ssl_enabled="(not found)"],
  [test "x$with_ssl" == xgnutls && test "x$with_gnutls" == xno], [ssl_enabled="(not found)"],
  [])

AC_MSG_NOTICE([Summary of build options:

  Version:            ${PACKAGE_VERSION}
  Host OS:            ${host_os}
  Install prefix:     ${prefix}
  Compiler:           ${CC}
  CFlags:             ${CFLAGS} ${CPPFLAGS} ${WARN_CFLAGS}
  LDFlags:            ${LDFLAGS}
  Libs:               ${LIBS}
  Library types:      shared=${enable_shared}, static=${enable_static}
  SSL/TLS support:    $with_ssl $ssl_enabled
  GZIP compression:   $with_zlib
  BZIP2 compression:  $with_bzip2
  LZMA compression:   $with_lzma
  Brotli compression: $with_brotlidec
  Zstd compression:   $with_zstd
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

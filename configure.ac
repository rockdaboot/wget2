#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
CFLAGS=$CFLAGS
LDFLAGS=$LDFLAGS

AC_PREREQ([2.67])
AC_INIT([wget2], [1.0.0], [bug-wget@gnu.org], [wget2], [https://savannah.gnu.org/projects/wget])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([subdir-objects parallel-tests gnu])

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

#if test "$CFLAGS" = ""; then
#  if test "$GCC" = "yes"; then
#   CFLAGS="-g -std=gnu99 -pedantic -fPIC\
# -Wall -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
# -Wwrite-strings -Wformat=2 -Wformat -Wformat-security\
# -Wsign-compare -Wextra -D_FORTIFY_SOURCE=2\
# -Wcast-align -O2"
#  fi
#else
#  CFLAGS="$CFLAGS -fPIC"
#fi
#if test "$LDFLAGS" = ""; then
#  if test "$GCC" = "yes"; then
##    LDFLAGS="-fPIE -pie -Wl,-z,relro,--as-needed"
#    LDFLAGS="-fPIE -pie -Wl,--as-needed -ffunction-sections"
#  fi
#fi
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

LT_PREREQ([2.2])
LT_INIT([dlopen disable-static])

# Define these substitions here to keep all version information in one place.
# For information on how to properly maintain the library version information,
# refer to the libtool manual, section "Updating library version information":
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
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

#
# gl_GCC_VERSION_IFELSE([major], [minor], [run-if-found], [run-if-not-found])
# ------------------------------------------------
# If $CPP is gcc-MAJOR.MINOR or newer, then run RUN-IF-FOUND.
# Otherwise, run RUN-IF-NOT-FOUND.
AC_DEFUN([gl_GCC_VERSION_IFELSE],
  [AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM(
      [[
#if ($1) < __GNUC__ || (($1) == __GNUC__ && ($2) <= __GNUC_MINOR__)
/* ok */
#else
# error "your version of gcc is older than $1.$2"
#endif
      ]]),
    ], [$3], [$4])
  ]
)

# gl_WORD_SET(RESULT, SET, WORDS)
# --------------------------------------------------
# Add each word in WORDS to SET if not already there.
# Words separated by whitespace.
AC_DEFUN([gl_WORD_SET],
[
  ret=$2
  words=" $2 "
  for word in $3; do
    if test "${words#*" $word "}" = "$words"; then ret="$ret $word"; fi
  done
  $1=$ret
])

# gl_WORD_REMOVE(RESULT, SET, WORDS)
# --------------------------------------------------
# Remove each word in WORDS from SET.
# Words separated by whitespace.
AC_DEFUN([gl_WORD_REMOVE],
[
  ret=
  words=" $3 "
  for word in $2; do
     if test "${words#*" $word "}" = "$words"; then ret="$ret $word"; fi
  done
  $1=$ret
])

#
# check if compiler warnings are requested
#
AC_ARG_ENABLE([gcc-warnings],
  [AS_HELP_STRING([--enable-gcc-warnings], [Turn on extra GCC warnings (for developers)])],
  [case $enableval in
     yes|no) ;;
     *) AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
   esac
     gl_gcc_warnings=$enableval
  ], [
    # GCC provides fine-grained control over diagnostics which
    # is used in gnulib for example to suppress warnings from
    # certain sections of code.  So if this is available and
    # we're running from a git repo, then auto enable the warnings.
    gl_gcc_warnings=no
    test -f .manywarnings && gl_gcc_warnings=yes
  ]
)

if test "$gl_gcc_warnings" = yes; then
  WARN_CFLAGS=$CFLAGS
  GNULIB_WARN_CFLAGS=$CFLAGS

  CCNAME=$($CC --version| { read name _; echo $name; })

  if test "$CCNAME" = "gcc"; then
    # add -Wall -Wextra to reduce number of warn flags
    gl_WORD_SET([WARN_CFLAGS], [$CFLAGS], ["-Wall -Wextra"])

    # collect all disabled warn flags in $WARN_CFLAGS
    WARN_CFLAGS=[$(gcc $WARN_CFLAGS -Q --help=warning,C|\
      awk '{ if (($2 == "[disabled]" || $2 == "") && index($1,"=")==0 && $1~/^-W/) print $1 }')]

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

    # remove unwanted warn flags
    gl_WORD_REMOVE([WARN_CFLAGS], [$WARN_CFLAGS], [$nw])

    # add more flags as you like
    WARN_CFLAGS="$WARN_CFLAGS -fdiagnostics-color=always"
    #WARN_CFLAGS="$WARN_CFLAGS -Werror"

    # We use a slightly smaller set of warning options for lib/.
    # Remove the following and save the result in GNULIB_WARN_CFLAGS.
    # Removing is not enough if these switches are implicitly set by other
    #  flags like -Wall or -Wextra. We have to explicitely unset them
    #  with -Wno-....
    nw=
    nw="$nw -Wpedantic"
    nw="$nw -Wunused-macros"
    nw="$nw -Wsign-compare"
    nw="$nw -Wunused-parameter"
    nw="$nw -Wswitch-default"
    nw="$nw -Wformat-nonliteral"
    nw="$nw -Wsuggest-attribute=pure"
    nw="$nw -Wunsafe-loop-optimizations"
    nw="$nw -Wundef"
    nw="$nw -Wswitch-enum"
    gl_WORD_REMOVE([GNULIB_WARN_CFLAGS], [$WARN_CFLAGS], [$nw])

    # disable options implicitly set by other options
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-sign-compare -Wno-unused-parameter"

  elif test "$CCNAME" = "clang"; then
    # setup flags for this project
	 gl_WORD_SET([WARN_CFLAGS], [$CFLAGS], ["-Weverything"])
    WARN_CFLAGS="$WARN_CFLAGS -Wno-system-headers -Wno-vla -Wno-cast-qual -Wno-padded"
    WARN_CFLAGS="$WARN_CFLAGS -Wno-reserved-id-macro -Wno-sign-conversion  -Wno-disabled-macro-expansion"

    # remove all flags from WARN_FLAGS that are already in CFLAGS
    gl_WORD_REMOVE([WARN_CFLAGS], [$WARN_CFLAGS], [$CFLAGS])

    # disable verbose options
    GNULIB_WARN_CFLAGS="$WARN_CFLAGS -Wno-sign-compare -Wno-unused-parameter -Wno-undef -Wno-format-nonliteral"
    GNULIB_WARN_CFLAGS="$GNULIB_WARN_CFLAGS -Wno-conversion -Wno-disabled-macro-expansion -Wno-c++98-compat -Wno-gnu-statement-expression"

    # remove all flags from GNULIB_WARN_FLAGS that are already in CFLAGS
    gl_WORD_REMOVE([GNULIB_WARN_CFLAGS], [$GNULIB_WARN_CFLAGS], [$CFLAGS])
  fi

  AC_SUBST([WARN_CFLAGS])
  AC_SUBST([GNULIB_WARN_CFLAGS])
fi

AC_ARG_ENABLE([fsanitize-ubsan],
  [AS_HELP_STRING([--enable-fsanitize-ubsan], [Turn on Undefined Behavior Sanitizer (for developers)])],
  [gl_cc_sanitize_ubsan=yes], [gl_cc_sanitize_ubsan=no])

AC_ARG_ENABLE([fsanitize-asan],
  [AS_HELP_STRING([--enable-fsanitize-asan], [Turn on Address Sanitizer (for developers)])],
  [gl_cc_sanitize_asan=yes], [gl_cc_sanitize_asan=no])

AC_ARG_ENABLE([fsanitize-msan],
  [AS_HELP_STRING([--enable-fsanitize-msan], [Turn on Memory Sanitizer (for developers)])],
  [gl_cc_sanitize_msan=yes], [gl_cc_sanitize_msan=no])

AC_ARG_ENABLE([fsanitize-tsan],
  [AS_HELP_STRING([--enable-fsanitize-tsan], [Turn on Thread Sanitizer (for developers)])],
  [gl_cc_sanitize_tsan=yes], [gl_cc_sanitize_tsan=no])


if test "$gl_cc_sanitize_asan" = yes; then
  if test "$gl_cc_sanitize_msan" = yes; then
    AC_MSG_ERROR([Address Sanitizer and Memory Sanitizer are mutually exclusive])
  elif test "gl_cc_sanitize_tsan" = yes; then
    AC_MSG_ERROR([Address Sanitizer and Thread Sanitizer are mutually exclusive])
  fi
fi

if test "$gl_cc_sanitize_ubsan" = yes; then
  gl_WARN_ADD([-fsanitize=undefined])
  gl_WARN_ADD([-fno-sanitize-recover=undefined])
fi

if test "$gl_cc_sanitize_asan" = yes; then
  gl_WARN_ADD([-fsanitize=address])
  gl_WARN_ADD([-fno-omit-frame-pointer])
fi

if test "$gl_cc_sanitize_msan" = yes; then
  gl_WARN_ADD([-fsanitize=memory])
  gl_WARN_ADD([-fno-omit-frame-pointer])
  gl_WARN_ADD([-fsanitize-memory-track-origins])
  gl_WARN_ADD([-fPIE])
fi

if test "$gl_cc_sanitize_tsan" = yes; then
  gl_WARN_ADD([-fsanitize=thread])
fi

#
# Assertions
#
AC_ARG_ENABLE([assert],
  [AS_HELP_STRING([--enable-assert], [Enable assertions in code (for developers)])],
  [ENABLE_ASSERT=$enableval], [ENABLE_ASSERT=no])

AS_IF([test "$ENABLE_ASSERT" != "yes"], [CFLAGS="-DNDEBUG $CFLAGS"], [])

#
# Gettext
#
m4_ifdef([AM_GNU_GETTEXT], [
  AM_GNU_GETTEXT([external],[need-ngettext])
  AC_CONFIG_FILES([po/Makefile.in])
  AM_CONDITIONAL([HAVE_PO], [true])
], [
  AM_CONDITIONAL([HAVE_PO], [false])
])
m4_ifdef([AM_GNU_GETTEXT_VERSION], [
#do not indent here
AM_GNU_GETTEXT_VERSION([0.18.1])
])

#
# check for doxygen
#
AC_CHECK_PROGS([DOXYGEN], [doxygen])
AS_IF([test -n "$DOXYGEN"], [
  AC_CONFIG_FILES([docs/Makefile docs/libwget.doxy])
  AC_SUBST([LIBWGET_DOCS], [docs])
], [
])

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


# Check for valgrind
AC_ARG_ENABLE(valgrind-tests,
  AS_HELP_STRING([--enable-valgrind-tests], [enable using Valgrind for tests]),
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

AC_ARG_WITH(gnutls, AS_HELP_STRING([--without-gnutls], [disable GNUTLS SSL support]), with_gnutls=$withval, with_gnutls=yes)
AS_IF([test "x$with_gnutls" != "xno"], [
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
  AC_SEARCH_LIBS(gnutls_hash, gnutls, [with_gnutls_hash=yes])
  AS_IF([test "x$with_gnutls" = xyes], [
    AC_CHECK_HEADERS([gnutls/ocsp.h])
    AC_CHECK_FUNCS(gnutls_srp_server_get_username gnutls_transport_get_int)
  ])
])
AM_CONDITIONAL([WITH_GNUTLS], [test "x$with_gnutls" = xyes])

AS_IF([test "x$with_gnutls" != xyes || test "x$with_gnutls_hash" != xyes], [
#  AC_SEARCH_LIBS(nettle_md5_init, nettle,
#    [with_libnettle=yes; AC_DEFINE([WITH_LIBNETTLE], [1], [Use libnettle])],
#    [with_libnettle=no;  AC_MSG_WARN(*** LIBNETTLE was not found. Fallback to libgcrypt for hashing and checksumming.)])

  AS_IF([test "x$with_libnettle" != xyes], [
    AC_SEARCH_LIBS(gcry_check_version, gcrypt,
      [with_gcrypt=yes; AC_DEFINE([WITH_GCRYPT], [1], [Use libgcrypt]) AC_CHECK_HEADERS([gcrypt.h])],
      [with_gcrypt=no;  AC_MSG_WARN(*** LIBGCRYPT was not found. Metalink checksumming and HTTP authentication are not available.)])
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
    [with_bzip2=yes; AC_DEFINE([WITH_BZIP2], [1], [Use libbz2])],
    [with_bzip2=no;  AC_MSG_WARN(*** libbz2 was not found. You will not be able to use BZIP2 (de)compression)])
])
AM_CONDITIONAL([WITH_BZIP2], [test "x$with_bzip2" = xyes])

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

AC_ARG_WITH(libidn2, AS_HELP_STRING([--without-libidn2], [disable IDN2 support]), with_libidn2=$withval, with_libidn2=yes)
AS_IF([test "x$with_libidn2" != xno], [
  AC_SEARCH_LIBS(idn2_lookup_u8, idn2,
    [with_libidn2=yes; AC_DEFINE([WITH_LIBIDN2], [1], [Use libidn2]) IDNA_INFO="IDNA 2008 (libidn2)"],
    [with_libidn2=no;  AC_MSG_WARN(*** LIBIDN2 was not found. You will not be able to use IDN2008 support)])
  AS_IF([test "x$with_libidn2" = xyes], [
    AC_SEARCH_LIBS(u8_tolower, unistring,
      [with_libunistring=yes; AC_DEFINE([WITH_LIBUNISTRING], [1], [Use libunistring]) IDNA_INFO="IDNA 2008 (libidn2+libunistring)"],
      [with_libunistring=no;  AC_MSG_WARN(*** LIBUNISTRING was not found. You will not be able to use IDN2008 on uppercase domains)])
  ])
])
AM_CONDITIONAL([WITH_LIBUNISTRING], [test "x$with_libunistring" = xyes])
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

# Checks for header files.
AC_CHECK_HEADERS([\
 crypt.h idna.h idn/idna.h idn2.h unicase.h netinet/tcp.h])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([\
 munmap strlcpy getuid])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 include/Makefile
                 include/wget/Makefile
                 libwget/Makefile
                 src/Makefile
                 data/Makefile
                 examples/Makefile
                 tests/Makefile
                 libwget.pc])
AC_OUTPUT

AC_MSG_NOTICE([Summary of build options:

  Version:           ${PACKAGE_VERSION}
  Host OS:           ${host_os}
  Install prefix:    ${prefix}
  Compiler:          ${CC}
  CFlags:            ${CFLAGS} ${CPPFLAGS} ${WARN_CFLAGS}
  LDFlags:           ${LDFLAGS}
  Libs:              ${LIBS}
  SSL/TLS support:   $with_gnutls
  GZIP compression:  $with_zlib
  BZIP2 compression: $with_bzip2
  LZMA compression:  $with_lzma
  IDNA support:      $IDNA_INFO
  PSL support:       $with_libpsl
  HTTP/2.0 support:  $with_libnghttp2
  Tests:             ${TESTS_INFO}
  Assertions:        $ENABLE_ASSERT
])

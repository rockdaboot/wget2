#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
CFLAGS=$CFLAGS
LDFLAGS=$LDFLAGS

AC_PREREQ([2.67])
AC_INIT([mget], [0.1.8], [mget-bugs@googlegroups.com], [mget], [https://github.com/rockdaboot/mget])
AM_INIT_AUTOMAKE

CFLAGS=$CFLAGS
AC_USE_SYSTEM_EXTENSIONS

LT_PREREQ([2.2])
LT_INIT([dlopen])

# Keep version info in configure.ac
# see also "Updating library version information" at
#   http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST([LIBMGET_SO_VERSION], [0:0:0])
AC_SUBST([LIBMGET_API_VERSION], [0.1])

AC_CONFIG_SRCDIR([src/mget.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Non-verbose make
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

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

# Checks for programs.

# If CFLAGS isn't defined and using gcc, set CFLAGS to something reasonable.
# Otherwise, just prevent autoconf from molesting CFLAGS.
#AC_PROG_CC
AC_PROG_CC_STDC

if test "$CFLAGS" = ""; then
  if test "$GCC" = "yes"; then
   CFLAGS="-g -std=gnu99 -pedantic -fPIC\
 -Wall -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
 -Wwrite-strings -Wformat=2 -Wformat -Wformat-security\
 -Wsign-compare -Wextra -D_FORTIFY_SOURCE=2\
 -Wcast-align -O2"
  fi
else
  CFLAGS="$CFLAGS -fPIC"
fi
if test "$LDFLAGS" = ""; then
  if test "$GCC" = "yes"; then
#    LDFLAGS="-fPIE -pie -Wl,-z,relro,--as-needed"
    LDFLAGS="-fPIE -pie -Wl,--as-needed -ffunction-sections"
  fi
fi
# Append EXTRA_CFLAGS to CFLAGS, if defined.
if test "$EXTRA_CFLAGS" != ""; then
  CFLAGS="$CFLAGS $EXTRA_CFLAGS"
fi
if test "$XTRA_CFLAGS" != ""; then
  CFLAGS="$CFLAGS $XTRA_CFLAGS"
fi

# Check for large file support.  This check needs to come fairly
# early because it could (in principle) affect whether functions and
# headers are available, whether they work, etc.
AC_SYS_LARGEFILE
AC_CHECK_SIZEOF(off_t)

#AM_NLS
#IT_PROG_INTLTOOL([0.40.0])
AC_PROG_LEX
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_CC_C_O

#
# Require C99 support
#
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = "no"; then
   AC_ERROR([Compiler does not support C99. Aborting.])
fi

#
# Gettext
#
AM_GNU_GETTEXT([external],[need-ngettext])
AM_GNU_GETTEXT_VERSION([0.18.1])

#
# check for gtk-doc
#
m4_ifdef([GTK_DOC_CHECK], [
GTK_DOC_CHECK([1.15],[--flavour no-tmpl])
],[
AM_CONDITIONAL([ENABLE_GTK_DOC], false)
])

#
# enable creation of man pages
#
AC_ARG_ENABLE(man,[AC_HELP_STRING([--enable-man],
                                  [generate man pages [default=auto]])],enable_man=yes,enable_man=no)

AS_IF([test "x$enable_man" != xno], [
  AC_PATH_PROG([XSLTPROC], [xsltproc])
  AS_IF([test -z "$XSLTPROC"], [
    AS_IF([test "$enable_man" = yes], [
      AC_MSG_ERROR([xsltproc is required for --enable-man])
    ])
    enable_man=no
  ])
])

#AC_PATH_PROG([XSLTPROC], [xsltproc])
AM_CONDITIONAL(ENABLE_MAN, test x$enable_man != xno)
AC_MSG_CHECKING([whether to generate man pages])
AS_IF([test "$enable_man" != no], [
  AC_MSG_RESULT([yes])
], [
  AC_MSG_RESULT([no])
])


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
AC_MSG_CHECKING([for __sync_fetch_and_add])
AC_LINK_IFELSE(
   [AC_LANG_SOURCE([
    int main(void) { return __sync_fetch_and_add((int *)0, 0); }
   ])],
   [AC_DEFINE([WITH_SYNC_FETCH_AND_ADD], [1], [use __sync_fetch_and_add]) AC_MSG_RESULT([yes])],
   [AC_MSG_RESULT([no])]
)

PKG_PROG_PKG_CONFIG

# Check for needed libraries
AC_SEARCH_LIBS(socket, ws2_32)
AC_SEARCH_LIBS(clock_gettime, rt)
AC_SEARCH_LIBS(pthread_create, pthread, [AC_DEFINE([HAVE_LIBPTHREAD], [1], [Use pthreads])])

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
      [with_gnutls=no;  AC_MSG_WARN(*** GNUTLS was not found. You will not be able to use HTTPS. Fallback to libnettle for Metalink checksumming.)])
  ])
  AC_SEARCH_LIBS(gnutls_hash, gnutls, [with_gnutls_hash=yes])
])
AM_CONDITIONAL([WITH_GNUTLS], [test "x$with_gnutls" = xyes])

AS_IF([test "x$with_gnutls" != xyes || test "x$with_gnutls_hash" != xyes], [
  AC_SEARCH_LIBS(nettle_md5_init, nettle,
    [with_libnettle=yes; AC_DEFINE([WITH_LIBNETTLE], [1], [Use libnettle])],
    [with_libnettle=no;  AC_MSG_WARN(*** LIBNETTLE was not found. Metalink checksumming is not available.)])
])
AM_CONDITIONAL([WITH_LIBNETTLE], [test "x$with_libnettle" = xyes])

AS_IF([test "x$with_gnutls" = xyes], [
  AC_CHECK_HEADERS([gnutls/ocsp.h])
])

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

AC_ARG_WITH(bz2, AS_HELP_STRING([--without-bzip2], [disable bzip2 compression support]), with_bzip2=$withval, with_bzip2=yes)
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
 fcntl.h inttypes.h libintl.h locale.h netdb.h netinet/in.h stddef.h stdlib.h string.h\
 strings.h sys/socket.h sys/time.h unistd.h crypt.h poll.h idna.h idn2.h stringprep.h\
 langinfo.h unicase.h fnmatch.h glob.h])

# Checks for typedefs, structures, and compiler characteristics.
#AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
#AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_FNMATCH
AC_CHECK_FUNCS([\
 clock_gettime dprintf dup2 futimens gettimeofday localtime_r memchr\
 memmove memset mkdir munmap select setlocale socket strcasecmp\
 strchr strdup strerror strncasecmp strndup strrchr strstr strlcpy \
 vasprintf nanosleep usleep iconv nl_langinfo futimens glob pwrite \
 qsort_r])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libmget/Makefile
                 src/Makefile
                 po/Makefile.in
                 docs/libmget/Makefile
                 data/Makefile
                 examples/Makefile
                 tests/Makefile
                 libmget-${LIBMGET_API_VERSION}.pc:libmget.pc.in])
AC_OUTPUT

AC_MSG_NOTICE([Summary of build options:

  Version:           ${PACKAGE_VERSION}
  Host OS:           ${host_os}
  Install prefix:    ${prefix}
  Compiler:          ${CC}
  CFlags:            ${CFLAGS} ${CPPFLAGS}
  LDFlags:           ${LDFLAGS}
  Libs:              ${LIBS}
  SSL support:       $with_gnutls
  GZIP compression:  $with_zlib
  BZIP2 compression: $with_bzip2
  LZMA compression:  $with_lzma
  IDNA support:      $IDNA_INFO
  PSL support:       $with_libpsl
  Tests:             ${TESTS_INFO}
])

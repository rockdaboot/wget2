#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mget], [0.1.2], [tim.ruehsen@gmx.de])
AC_CONFIG_SRCDIR([src/mget.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.

# If CFLAGS isn't defined and using gcc, set CFLAGS to something reasonable.
# Otherwise, just prevent autoconf from molesting CFLAGS.
CFLAGS=$CFLAGS
LDFLAGS=$LDFLAGS
AC_PROG_CC
echo CFLAGS="$CFLAGS" GCC="$GCC"
if test "x$CFLAGS" = "x" ; then
  if test "x$GCC" = "xyes" ; then
   CFLAGS="-g -std=gnu99 -pedantic -fPIC\
 -Wall -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes\
 -Wwrite-strings -Wformat=2 -Wformat -Wformat-security\
 -fstack-protector --param ssp-buffer-size=4\
 -Wno-sign-compare -Wextra -D_FORTIFY_SOURCE=2\
 -Wcast-align -O2"
  fi
fi
echo LDFLAGS="$LDFLAGS" GCC="$GCC"
if test "x$LDFLAGS" = "x" ; then
  if test "x$GCC" = "xyes" ; then
    LDFLAGS="-fPIE -pie -Wl,-z,relro,--as-needed"
  fi
fi
dnl Append EXTRA_CFLAGS to CFLAGS, if defined.
if test "x$EXTRA_CFLAGS" != "x" ; then
  CFLAGS="$CFLAGS $EXTRA_CFLAGS"
fi

AC_PROG_LEX
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lgnutls':
AC_CHECK_LIB([gnutls], [gnutls_global_init])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [pthread_attr_init])
# FIXME: Replace `main' with a function in `-lrt':
AC_CHECK_LIB([rt], [clock_gettime])
# FIXME: Replace `main' with a function in `-lz':
AC_CHECK_LIB([z], [inflate])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h libintl.h locale.h netdb.h netinet/in.h stddef.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
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
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([clock_gettime dup2 gettimeofday localtime_r memchr memmove memset mkdir munmap select setlocale socket strcasecmp strchr strdup strerror strncasecmp strndup strrchr strstr strlcpy])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tests/Makefile])
AC_OUTPUT

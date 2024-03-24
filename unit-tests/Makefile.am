DEFS = @DEFS@ -DSRCDIR=\"$(abs_srcdir)\" -DEXEEXT=\"$(EXEEXT)\"

MYLIBS = \
 $(CLOCK_TIME_LIB) \
 $(GETADDRINFO_LIB) \
 $(GETHOSTNAME_LIB) \
 $(GETLOGIN_LIB) \
 $(GETRANDOM_LIB) \
 $(HARD_LOCALE_LIB) \
 $(HOSTENT_LIB) \
 $(INET_NTOP_LIB) \
 $(INET_PTON_LIB) \
 $(LIBMULTITHREAD) \
 $(LIBSOCKET) \
 $(LIBTHREAD) \
 $(LIB_CRYPTO) \
 $(LTLIBC32CONV) \
 $(LTLIBICONV) \
 $(LTLIBINTL) \
 $(LTLIBUNISTRING) \
 $(MBRTOWC_LIB) \
 $(NANOSLEEP_LIB) \
 $(POLL_LIB) \
 $(POSIX_SPAWN_LIB) \
 $(PTHREAD_SIGMASK_LIB) \
 $(SELECT_LIB) \
 $(SERVENT_LIB) \
 $(SETLOCALE_LIB) \
 $(SETLOCALE_NULL_LIB) \
 @INTL_MACOSX_LIBS@ \
 $(LIBS) $(CODE_COVERAGE_LIBS)

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) $(CODE_COVERAGE_CFLAGS) -DMALLOC_RETURNS_NONNULL
AM_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" $(CODE_COVERAGE_CPPFLAGS) \
 -DMALLOC_RETURNS_NONNULL

LDADD = ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

BASE_OBJS = \
  ../src/log.o \
  ../src/options.o \
  ../src/stats_server.o \
  ../src/stats_site.o \
  ../src/utils.o \
  ../src/dl.o \
  ../src/plugin.o \
  ../src/testing.o

if WITH_GPGME
  BASE_OBJS += ../src/gpgme.o
endif

WGET_TESTS = \
 test$(EXEEXT) \
 test-parse-html$(EXEEXT) \
 test-cond$(EXEEXT) \
 test-decompress$(EXEEXT)

if PLUGIN_SUPPORT
 WGET_TESTS += test-dl$(EXEEXT)
 check_LTLIBRARIES = libalpha.la libbeta.la
endif

check_PROGRAMS = buffer_printf_perf stringmap_perf $(WGET_TESTS)

test_SOURCES = test.c
test_LDADD = $(BASE_OBJS) ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)
test_parse_html_LDADD = $(BASE_OBJS) ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)
test_dl_LDADD = ../src/dl.o ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

EXTRA_DIST = files

AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";
TESTS = $(WGET_TESTS)

#Dummy libraries for dynamic loading related testing
dummy_ldflags = -avoid-version -module -shared -no-undefined \
	-rpath $(abs_builddir)

libalpha_la_SOURCES = test-dl-dummy.c
libalpha_la_CPPFLAGS = $(AM_CPPFLAGS) -DPARAM=alpha
libalpha_la_LIBADD = $(LDADD)
libalpha_la_LDFLAGS = $(dummy_ldflags)

libbeta_la_SOURCES = test-dl-dummy.c
libbeta_la_CPPFLAGS = $(AM_CPPFLAGS) -DPARAM=beta
libbeta_la_LIBADD = $(LDADD)
libbeta_la_LDFLAGS = $(dummy_ldflags)

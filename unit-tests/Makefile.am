DEFS = @DEFS@ -DWGET_DATADIR=\"$(abs_top_srcdir)/data\" -DSRCDIR=\"$(abs_srcdir)\" -DEXEEXT=\"$(EXEEXT)\"

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -Wno-missing-field-initializers -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
LDADD = ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LIBICONV) $(LIBINTL) $(LIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)

WGET_TESTS = \
 test$(EXEEXT) \
 test-parse-html$(EXEEXT)

if PLUGIN_SUPPORT
 WGET_TESTS += test-dl$(EXEEXT)
 check_LTLIBRARIES = libalpha.la libbeta.la
endif

check_PROGRAMS = buffer_printf_perf stringmap_perf $(WGET_TESTS)

test_SOURCES = test.c
test_LDADD = ../src/log.o ../src/options.o ../src/stats.o ../src/dl.o ../src/plugin.o ../src/testing.o \
 ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)
test_parse_html_LDADD = ../src/log.o ../src/options.o ../src/stats.o ../src/dl.o ../src/plugin.o ../src/testing.o \
 ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)
test_dl_LDADD = ../src/dl.o ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) \
 @INTL_MACOSX_LIBS@ $(LIBS)

EXTRA_DIST = files
dist-hook:
	rm -f $(distdir)/files/elb_bibel.txt

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

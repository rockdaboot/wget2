DEFS = @DEFS@ -DDATADIR=\"$(abs_top_srcdir)/data\" -DSRCDIR=\"$(abs_srcdir)\" -DEXEEXT=\"$(EXEEXT)\"

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -Wno-missing-field-initializers -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
AM_LDFLAGS = -static
LDADD = ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LIBICONV) $(LIBINTL) $(LIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)

WGET_TESTS = \
 test$(EXEEXT) \
 test-parse-html$(EXEEXT) \
 test-dl$(EXEEXT)

check_PROGRAMS = buffer_printf_perf stringmap_perf $(WGET_TESTS)
check_LTLIBRARIES = libalpha.la libbeta.la

test_SOURCES = test.c
test_LDADD = ../src/log.o ../src/options.o ../src/dl.o ../src/plugin.o \
 ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)
test_parse_html_LDADD = ../src/log.o ../src/options.o ../src/dl.o ../src/plugin.o \
 ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)
test_cookies_http_state_LDADD = ../src/log.o ../src/options.o ../src/dl.o ../src/plugin.o \
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
libalpha_la_LDFLAGS = $(dummy_ldflags)

libbeta_la_SOURCES = test-dl-dummy.c
libbeta_la_CPPFLAGS = $(AM_CPPFLAGS) -DPARAM=beta
libbeta_la_LDFLAGS = $(dummy_ldflags)

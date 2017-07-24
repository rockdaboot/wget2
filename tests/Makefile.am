DEFS = @DEFS@ -DDATADIR=\"$(abs_top_srcdir)/data\" -DSRCDIR=\"$(abs_srcdir)\" -DEXEEXT=\"$(EXEEXT)\"

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -Wno-missing-field-initializers -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
AM_LDFLAGS = -static
LDADD = libtest.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LIBICONV) $(LIBINTL) $(LIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)

# test-iri-disabled removed since Wget2 always uses IRIs
WGET_TESTS = test-wget-1$(EXEEXT) test-c-r$(EXEEXT) test-restrict-ascii$(EXEEXT) test-i-http$(EXEEXT) test-i-https$(EXEEXT)\
 test-np$(EXEEXT) test--spider-r$(EXEEXT) test-meta-robots$(EXEEXT) test-idn-robots$(EXEEXT) test-idn-meta$(EXEEXT)\
 test-idn-cmd$(EXEEXT) test-iri$(EXEEXT) test-iri-percent$(EXEEXT) test-iri-list$(EXEEXT) test-iri-forced-remote$(EXEEXT)\
 test-auth-basic$(EXEEXT) test-parse-rss$(EXEEXT) test--page-requisites$(EXEEXT)\
 test--accept$(EXEEXT) test-k$(EXEEXT) test--follow-tags$(EXEEXT) test-directory-clash$(EXEEXT) test-redirection$(EXEEXT)\
 test-base$(EXEEXT) test-metalink$(EXEEXT) test-robots$(EXEEXT) test-parse-css$(EXEEXT) test-bad-chunk$(EXEEXT)\
 test-iri-subdir$(EXEEXT) test-chunked$(EXEEXT) test-cut-dirs$(EXEEXT) test-parse-html-css$(EXEEXT)

#test--post-file test-E-k test-cookies-http_state

if PLUGIN_SUPPORT
 WGET_TESTS += test-plugin$(EXEEXT)
 check_LTLIBRARIES = libpluginname.la libpluginexit.la libpluginoption.la libpluginfaulty1.la libpluginfaulty2.la \
  libpluginapi.la
endif

check_PROGRAMS = $(WGET_TESTS)

noinst_LTLIBRARIES = libtest.la
libtest_la_SOURCES = libtest.c
libtest_la_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include/wget -I$(top_builddir)/lib -I$(top_srcdir)/lib $(CFLAG_VISIBILITY) -DBUILDING_LIBWGET \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
libtest_la_LIBADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

EXTRA_DIST = libtest.h certs

clean-local:
	rm -rf $(srcdir)/.test_*

AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";
TESTS = $(WGET_TESTS)

#Test plugins for plugin related testing
dummy_ldflags = -avoid-version -module -shared -no-undefined \
	-rpath $(abs_builddir)

libpluginname_la_SOURCES = test-plugin-dummy.c
libpluginname_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_NAME
libpluginname_la_LDFLAGS = $(dummy_ldflags)
libpluginname_la_LIBADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

libpluginexit_la_SOURCES = test-plugin-dummy.c
libpluginexit_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_EXITSTATUS
libpluginexit_la_LDFLAGS = $(dummy_ldflags)
libpluginexit_la_LIBADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

libpluginfaulty1_la_SOURCES = test-plugin-dummy.c
libpluginfaulty1_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_FAULTY1
libpluginfaulty1_la_LDFLAGS = $(dummy_ldflags)
libpluginfaulty1_la_LIBADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

libpluginfaulty2_la_SOURCES = test-plugin-dummy.c
libpluginfaulty2_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_FAULTY2
libpluginfaulty2_la_LDFLAGS = $(dummy_ldflags)
libpluginfaulty2_la_LIBADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

libpluginoption_la_SOURCES = test-plugin-dummy.c
libpluginoption_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_OPTIONS
libpluginoption_la_LDFLAGS = $(dummy_ldflags)
libpluginoption_la_LIBADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

libpluginapi_la_SOURCES = test-plugin-dummy.c
libpluginapi_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_API
libpluginapi_la_LDFLAGS = $(dummy_ldflags)
libpluginapi_la_LIBADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

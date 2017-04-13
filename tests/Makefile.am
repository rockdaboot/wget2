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
WGET_TESTS = test$(EXEEXT) test-wget-1$(EXEEXT) test-restrict-ascii$(EXEEXT) test-i-http$(EXEEXT) test-i-https$(EXEEXT)\
 test-np$(EXEEXT) test--spider-r$(EXEEXT) test-meta-robots$(EXEEXT) test-idn-robots$(EXEEXT) test-idn-meta$(EXEEXT)\
 test-idn-cmd$(EXEEXT) test-iri$(EXEEXT) test-iri-percent$(EXEEXT) test-iri-list$(EXEEXT) test-iri-forced-remote$(EXEEXT)\
 test-auth-basic$(EXEEXT) test-parse-html$(EXEEXT) test-parse-rss$(EXEEXT) test--page-requisites$(EXEEXT)\
 test--accept$(EXEEXT) test-k$(EXEEXT) test--follow-tags$(EXEEXT) test-directory-clash$(EXEEXT) test-redirection$(EXEEXT)\
 test-base$(EXEEXT) test-metalink$(EXEEXT) test-robots$(EXEEXT) test-parse-css$(EXEEXT) test-bad-chunk$(EXEEXT)\
 test-iri-subdir$(EXEEXT) test-chunked$(EXEEXT) test-cut-dirs$(EXEEXT) test-parse-html-css$(EXEEXT) test-cut-get-vars$(EXEEXT)

#test--post-file test-E-k test-cookies-http_state

check_PROGRAMS = buffer_printf_perf stringmap_perf $(WGET_TESTS)

test_SOURCES = test.c
test_LDADD = ../src/log.o ../src/options.o libtest.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)
test_parse_html_LDADD = ../src/log.o ../src/options.o libtest.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)
test_cookies_http_state_LDADD = ../src/log.o ../src/options.o libtest.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)

noinst_LTLIBRARIES = libtest.la
libtest_la_SOURCES = libtest.c
libtest_la_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include/wget -I$(top_builddir)/lib -I$(top_srcdir)/lib $(CFLAG_VISIBILITY) -DBUILDING_LIBWGET \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" \
 -DVGSUPPFILE=\"$(abs_srcdir)/valgrind-suppressions\"
libtest_la_LIBADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

EXTRA_DIST = files libtest.h certs
dist-hook:
	rm -f $(distdir)/files/elb_bibel.txt
#	cp $(top_srcdir)/data/public_suffixes.txt $(distdir)/files/
#	rm -rf `find $(distdir)/files -name CVS`

clean-local:
	rm -rf $(srcdir)/.test_*

AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";
TESTS = $(WGET_TESTS)

#DEFS = @DEFS@ -DDATADIR=\"$(datadir)/@PACKAGE@\" -DSRCDIR=\"$(srcdir)\"
DEFS = @DEFS@ -DDATADIR=\"$(abs_top_srcdir)/data\" -DSRCDIR=\"$(srcdir)\"
AM_CPPFLAGS = -Wno-missing-field-initializers -I$(top_srcdir)/include -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib
AM_LDFLAGS = -static
LDADD = libtest.la ../libwget/libwget.la @LTLIBICONV@\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL)\
 $(LIB_SELECT) $(LIBINTL) $(SERVENT_LIB) $(LIBS) ../lib/libgnu.a

# test-iri-disabled removed since Wget always uses IRIs
WGET_TESTS = test test-wget-1 test-restrict-ascii test-i-http test-i-https test-np test--spider-r \
 test-meta-robots test-idn-robots test-idn-meta test-idn-cmd \
 test-iri test-iri-percent test-iri-list test-iri-forced-remote \
 test-auth-basic test-parse-html test-parse-rss test--page-requisites test--accept \
 test-k test--follow-tags test-directory-clash test-redirection test-base

#test--post-file test-E-k

check_PROGRAMS = buffer_printf2_perf stringmap_perf $(WGET_TESTS)

test_SOURCES = test.c
test_LDADD = ../libwget/libwget.la ../src/log.o ../src/options.o @LTLIBICONV@\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL)\
 $(LIB_SELECT) $(LIBINTL) $(SERVENT_LIB) $(LIBS) ../lib/libgnu.a
test_parse_html_LDADD = ../libwget/libwget.la ../src/log.o ../src/options.o @LTLIBICONV@\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL)\
 $(LIB_SELECT) $(LIBINTL) $(SERVENT_LIB) $(LIBS) ../lib/libgnu.a

noinst_LTLIBRARIES = libtest.la
libtest_la_SOURCES = libtest.c
libtest_la_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include -I$(top_builddir)/lib -I$(top_srcdir)/lib
#libtest_LDADD = libtest.o

EXTRA_DIST = files libtest.h certs
dist-hook:
	rm -f $(distdir)/files/elb_bibel.txt
#	cp $(top_srcdir)/data/public_suffixes.txt $(distdir)/files/
#	rm -rf `find $(distdir)/files -name CVS`

clean-local:
	rm -rf $(srcdir)/.test_*

#AM_TESTS_ENVIRONMENT = VALGRIND_TESTS"=@VALGRIND_ENVIRONMENT@"
AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";
TESTS = $(WGET_TESTS)

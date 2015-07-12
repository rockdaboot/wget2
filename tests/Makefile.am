#DEFS = @DEFS@ -DDATADIR=\"$(datadir)/@PACKAGE@\" -DSRCDIR=\"$(srcdir)\"
DEFS = @DEFS@ -DDATADIR=\"$(top_srcdir)/data\" -DSRCDIR=\"$(srcdir)\"
AM_CPPFLAGS = -Wno-missing-field-initializers -I$(top_srcdir)/include
AM_LDFLAGS = -static
LDADD = libtest.la ../libmget/libmget-@LIBMGET_API_VERSION@.la @LTLIBICONV@ @LTLIBINTL@

# test-iri-disabled removed since Mget always uses IRIs
MGET_TESTS = test test-mget-1 test-restrict-ascii test-i-http test-i-https test-np test--spider-r \
 test-meta-robots test-idn-robots test-idn-meta test-idn-cmd \
 test-iri test-iri-percent test-iri-list test-iri-forced-remote \
 test-auth-basic test-parse-html test-parse-rss test--page-requisites test--accept \
 test-k test--follow-tags test-directory-clash test-ftp test-ftps

#test--post-file test-E-k

check_PROGRAMS = buffer_printf2_perf stringmap_perf $(MGET_TESTS)

test_SOURCES = test.c
test_LDADD = ../libmget/libmget-@LIBMGET_API_VERSION@.la ../src/mget-log.o ../src/mget-options.o @LTLIBICONV@ @LTLIBINTL@
test_parse_html_LDADD = ../libmget/libmget-@LIBMGET_API_VERSION@.la ../src/mget-log.o ../src/mget-options.o @LTLIBICONV@ @LTLIBINTL@

noinst_LTLIBRARIES = libtest.la
libtest_la_SOURCES = libtest.c
libtest_la_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include
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
TESTS = $(MGET_TESTS)

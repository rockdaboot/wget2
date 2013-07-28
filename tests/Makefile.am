#DEFS = @DEFS@ -DDATADIR=\"$(datadir)/@PACKAGE@\" -DSRCDIR=\"$(srcdir)\"
DEFS = @DEFS@ -DDATADIR=\"$(top_srcdir)/data\" -DSRCDIR=\"$(srcdir)\"
AM_CPPFLAGS = -Wno-missing-field-initializers -I$(top_srcdir)/include
AM_LDFLAGS = -static
LDADD = $(top_srcdir)/libmget/libmget.la libtest.o

MGET_TESTS = test test-mget-1 test-restrict-ascii test-i-http test-np test--spider-r \
 test--post-file test-E-k test-k test-meta-robots test-idn-robots test-idn-meta test-idn-cmd \
 test-iri test-iri-disabled test-iri-percent test-iri-list test-iri-forced-remote \
 test-auth-basic

check_PROGRAMS = buffer_printf2_perf stringmap_perf $(MGET_TESTS)

test_SOURCES = test.c
test_LDADD = $(top_srcdir)/libmget/libmget.la $(top_srcdir)/src/mget-log.o $(top_srcdir)/src/mget-options.o

#libtest_SOURCES = libtest.c
#libtest_CPPFLAGS = -I$(top_srcdir)/include
#libtest_LDADD = libtest.o

EXTRA_DIST = files
dist-hook:
	rm -f $(distdir)/files/elb_bibel.txt
#	cp $(top_srcdir)/data/public_suffixes.txt $(distdir)/files/
#	rm -rf `find $(distdir)/files -name CVS`

#dist-hook:
#	mkdir $(distdir)/random
#	cp -p $(srcdir)/random/a1 $(srcdir)/random/a2 $(distdir)/random

TESTS_ENVIRONMENT = @VALGRIND_ENVIRONMENT@
#TESTS = test $(MGET_TESTS)
TESTS = $(MGET_TESTS)

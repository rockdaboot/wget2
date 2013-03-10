#DEFS = @DEFS@ -DDATADIR=\"$(datadir)/@PACKAGE@\" -DSRCDIR=\"$(srcdir)\"
DEFS = @DEFS@ -DDATADIR=\"$(top_srcdir)/data\" -DSRCDIR=\"$(srcdir)\"

check_PROGRAMS = test buffer_printf2_perf stringmap_perf test_basic

test_SOURCES = test.c
test_CPPFLAGS = -I$(top_srcdir)/include
test_LDADD = ../libmget/libmget.la ../src/mget-log.o ../src/mget-options.o

#libtest_SOURCES = libtest.c
#libtest_CPPFLAGS = -I$(top_srcdir)/include
#libtest_LDADD = libtest.o

buffer_printf2_perf_SOURCES = buffer_printf2_perf.c
buffer_printf2_perf_CPPFLAGS = -I$(top_srcdir)/include
buffer_printf2_perf_LDADD = ../libmget/libmget.la

stringmap_perf_SOURCES = stringmap_perf.c
stringmap_perf_CPPFLAGS = -I$(top_srcdir)/include
stringmap_perf_LDADD = ../libmget/libmget.la

test_basic_SOURCES = test_basic.c libtest.c
test_basic_CPPFLAGS = -I$(top_srcdir)/include
test_basic_LDADD = ../libmget/libmget.la

EXTRA_DIST = files
dist-hook:
	rm -f $(distdir)/files/elb_bibel.txt
#	cp $(top_srcdir)/data/public_suffixes.txt $(distdir)/files/
#	rm -rf `find $(distdir)/files -name CVS`

#dist-hook:
#	mkdir $(distdir)/random
#	cp -p $(srcdir)/random/a1 $(srcdir)/random/a2 $(distdir)/random

TESTS_ENVIRONMENT = @VALGRIND_ENVIRONMENT@
TESTS = test test_basic

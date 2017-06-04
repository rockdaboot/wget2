AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) -Wno-unused-parameter
AM_CXXFLAGS = $(WERROR_CFLAGS) -Wall -Wextra
AM_CPPFLAGS = -Wno-missing-field-initializers -I$(top_srcdir)/include/wget -I$(srcdir) \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" -DSRCDIR=\"$(abs_srcdir)\" -DTEST_RUN
AM_LDFLAGS = -static
LDADD = ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LIBICONV) $(LIBINTL) $(LIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)

WGET_TESTS = \
 libwget_bar_fuzzer$(EXEEXT) \
 libwget_memtohex_fuzzer$(EXEEXT) \
 libwget_metalink_parse_fuzzer$(EXEEXT) \
 libwget_robots_parse_fuzzer$(EXEEXT) \
 libwget_xml_parse_buffer_fuzzer$(EXEEXT)

check_PROGRAMS = $(WGET_TESTS)

libwget_memtohex_fuzzer_SOURCES = libwget_memtohex_fuzzer.cc main.c
libwget_bar_fuzzer_SOURCES = libwget_bar_fuzzer.cc main.c
libwget_metalink_parse_fuzzer_SOURCES = libwget_metalink_parse_fuzzer.cc main.c
libwget_robots_parse_fuzzer_SOURCES = libwget_robots_parse_fuzzer.cc main.c
libwget_xml_parse_buffer_fuzzer_SOURCES = libwget_xml_parse_buffer_fuzzer.cc main.c

EXTRA_DIST = $(wildcard *.options) $(wildcard *.dict) \
 $(wildcard *.in/*) $(wildcard *.repro/*)

#dist-hook:
#	rm -f $(distdir)/files/elb_bibel.txt

AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";
TESTS = $(WGET_TESTS)

fuzz-coverage: $(WGET_TESTS)
	find . -name '*_fuzzer' -exec ./coverage.sh '{}' ';'

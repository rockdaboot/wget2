AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) -Wno-unused-parameter
AM_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(srcdir) \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" -DSRCDIR=\"$(abs_srcdir)\" -DTEST_RUN
AM_LDFLAGS = -static
LDADD = ../lib/libgnu.la ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LIBICONV) $(LIBINTL) $(LIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS)

WGET_TESTS = \
 libwget_atom_url_fuzzer$(EXEEXT) \
 libwget_bar_fuzzer$(EXEEXT) \
 libwget_base64_fuzzer$(EXEEXT) \
 libwget_cookie_fuzzer$(EXEEXT) \
 libwget_css_url_fuzzer$(EXEEXT) \
 libwget_hpkp_fuzzer$(EXEEXT) \
 libwget_html_url_fuzzer$(EXEEXT) \
 libwget_http_parse_fuzzer$(EXEEXT) \
 libwget_iri_fuzzer$(EXEEXT) \
 libwget_metalink_parse_fuzzer$(EXEEXT) \
 libwget_robots_parse_fuzzer$(EXEEXT) \
 libwget_sitemap_url_fuzzer$(EXEEXT) \
 libwget_utils_fuzzer$(EXEEXT) \
 libwget_xml_parse_buffer_fuzzer$(EXEEXT)

check_PROGRAMS = $(WGET_TESTS)

libwget_atom_url_fuzzer_SOURCES = libwget_atom_url_fuzzer.c main.c fuzzer.h
libwget_bar_fuzzer_SOURCES = libwget_bar_fuzzer.c main.c fuzzer.h
libwget_base64_fuzzer_SOURCES = libwget_base64_fuzzer.c main.c fuzzer.h
libwget_cookie_fuzzer_SOURCES = libwget_cookie_fuzzer.c main.c fuzzer.h
libwget_css_url_fuzzer_SOURCES = libwget_css_url_fuzzer.c main.c fuzzer.h
libwget_hpkp_fuzzer_SOURCES = libwget_hpkp_fuzzer.c main.c fuzzer.h
libwget_html_url_fuzzer_SOURCES = libwget_html_url_fuzzer.c main.c fuzzer.h
libwget_http_parse_fuzzer_SOURCES = libwget_http_parse_fuzzer.c main.c fuzzer.h
libwget_iri_fuzzer_SOURCES = libwget_iri_fuzzer.c main.c fuzzer.h
libwget_metalink_parse_fuzzer_SOURCES = libwget_metalink_parse_fuzzer.c main.c fuzzer.h
libwget_robots_parse_fuzzer_SOURCES = libwget_robots_parse_fuzzer.c main.c fuzzer.h
libwget_sitemap_url_fuzzer_SOURCES = libwget_sitemap_url_fuzzer.c main.c fuzzer.h
libwget_utils_fuzzer_SOURCES = libwget_utils_fuzzer.c main.c fuzzer.h
libwget_xml_parse_buffer_fuzzer_SOURCES = libwget_xml_parse_buffer_fuzzer.c main.c fuzzer.h

#EXTRA_DIST = $(wildcard *.options) $(wildcard *.dict) \
# $(wildcard *.in) $(wildcard *.repro)

dist-hook:
	find . -name '*.options' -exec cp -v '{}' $(distdir) ';'
	find . -name '*.dict' -exec cp -v '{}' $(distdir) ';'
	find . -name '*.in' -exec cp -vr '{}' $(distdir) ';'
	find . -name '*.repro' -exec cp -vr '{}' $(distdir) ';'

AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";
TESTS = $(WGET_TESTS)

clean-local:
	rm -rf *.gc?? *.log lcov

oss-fuzz:
	if test "$$OUT" != ""; then \
	for ccfile in *_fuzzer.c; do \
	fuzzer=$$(basename $$ccfile .c); \
	XLIBS="-lpsl -lgnutls -lnettle -lhogweed -lidn2 -lunistring"; \
	$$CXX $$CXXFLAGS -I$(top_srcdir)/include/wget/ -I$(top_srcdir) \
	"$${fuzzer}.c" -o "$${fuzzer}" \
	../libwget/.libs/libwget.a $${LIB_FUZZING_ENGINE} \
	-Wl,-Bstatic \
	$${XLIBS} \
	-Wl,-Bdynamic -lgnutls; \
	done; \
	fi

.PHONY: oss-fuzz

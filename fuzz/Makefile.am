AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 $(CODE_COVERAGE_CPPFLAGS) \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" -DSRCDIR=\"$(abs_srcdir)\"
LDADD = ../lib/libgnu.la ../libwget/libwget.la \
 $(CLOCK_TIME_LIB) \
 $(GETADDRINFO_LIB) \
 $(GETHOSTNAME_LIB) \
 $(GETLOGIN_LIB) \
 $(GETRANDOM_LIB) \
 $(HARD_LOCALE_LIB) \
 $(HOSTENT_LIB) \
 $(INET_NTOP_LIB) \
 $(INET_PTON_LIB) \
 $(LIBMULTITHREAD) \
 $(LIBSOCKET) \
 $(LIBTHREAD) \
 $(LIB_CRYPTO) \
 $(LTLIBC32CONV) \
 $(LTLIBICONV) \
 $(LTLIBINTL) \
 $(LTLIBUNISTRING) \
 $(MBRTOWC_LIB) \
 $(NANOSLEEP_LIB) \
 $(POLL_LIB) \
 $(POSIX_SPAWN_LIB) \
 $(PTHREAD_SIGMASK_LIB) \
 $(SELECT_LIB) \
 $(SERVENT_LIB) \
 $(SETLOCALE_LIB) \
 $(SETLOCALE_NULL_LIB) \
 @INTL_MACOSX_LIBS@ \
 $(FUZZ_LIBS) $(CODE_COVERAGE_LIBS)

WGET_TESTS = \
 libwget_atom_url_fuzzer$(EXEEXT) \
 libwget_bar_fuzzer$(EXEEXT) \
 libwget_base64_fuzzer$(EXEEXT) \
 libwget_cookie_fuzzer$(EXEEXT) \
 libwget_css_url_fuzzer$(EXEEXT) \
 libwget_hpkp_fuzzer$(EXEEXT) \
 libwget_hsts_fuzzer$(EXEEXT) \
 libwget_html_url_fuzzer$(EXEEXT) \
 libwget_http_client_fuzzer$(EXEEXT) \
 libwget_http_parse_fuzzer$(EXEEXT) \
 libwget_iri_fuzzer$(EXEEXT) \
 libwget_metalink_parse_fuzzer$(EXEEXT) \
 libwget_netrc_fuzzer$(EXEEXT) \
 libwget_ocsp_fuzzer$(EXEEXT) \
 libwget_robots_parse_fuzzer$(EXEEXT) \
 libwget_sitemap_url_fuzzer$(EXEEXT) \
 libwget_tlssess_fuzzer$(EXEEXT) \
 libwget_utils_fuzzer$(EXEEXT) \
 libwget_xml_parse_buffer_fuzzer$(EXEEXT) \
 wget_options_fuzzer$(EXEEXT)

if FUZZING
  bin_PROGRAMS = $(WGET_TESTS)
  LDADD += $(LIB_FUZZING_ENGINE)
  AM_LDFLAGS = -no-install
else
  AM_CPPFLAGS += -DTEST_RUN
  AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";
  TESTS = $(WGET_TESTS)
  check_PROGRAMS = $(WGET_TESTS)
  MAIN = main.c fuzzer.h
endif

libwget_atom_url_fuzzer_SOURCES = libwget_atom_url_fuzzer.c $(MAIN)
libwget_bar_fuzzer_SOURCES = libwget_bar_fuzzer.c $(MAIN)
libwget_base64_fuzzer_SOURCES = libwget_base64_fuzzer.c $(MAIN)
libwget_cookie_fuzzer_SOURCES = libwget_cookie_fuzzer.c $(MAIN)
libwget_css_url_fuzzer_SOURCES = libwget_css_url_fuzzer.c $(MAIN)
libwget_hpkp_fuzzer_SOURCES = libwget_hpkp_fuzzer.c $(MAIN)
libwget_hsts_fuzzer_SOURCES = libwget_hsts_fuzzer.c $(MAIN)
libwget_html_url_fuzzer_SOURCES = libwget_html_url_fuzzer.c $(MAIN)
libwget_http_client_fuzzer_SOURCES = libwget_http_client_fuzzer.c $(MAIN)
libwget_http_parse_fuzzer_SOURCES = libwget_http_parse_fuzzer.c $(MAIN)
libwget_iri_fuzzer_SOURCES = libwget_iri_fuzzer.c $(MAIN)
libwget_metalink_parse_fuzzer_SOURCES = libwget_metalink_parse_fuzzer.c $(MAIN)
libwget_netrc_fuzzer_SOURCES = libwget_netrc_fuzzer.c $(MAIN)
libwget_ocsp_fuzzer_SOURCES = libwget_ocsp_fuzzer.c $(MAIN)
libwget_robots_parse_fuzzer_SOURCES = libwget_robots_parse_fuzzer.c $(MAIN)
libwget_sitemap_url_fuzzer_SOURCES = libwget_sitemap_url_fuzzer.c $(MAIN)
libwget_tlssess_fuzzer_SOURCES = libwget_tlssess_fuzzer.c $(MAIN)
libwget_utils_fuzzer_SOURCES = libwget_utils_fuzzer.c $(MAIN)
libwget_xml_parse_buffer_fuzzer_SOURCES = libwget_xml_parse_buffer_fuzzer.c $(MAIN)
wget_options_fuzzer_SOURCES = wget_options_fuzzer.c $(MAIN)
if WITH_GPGME
  wget_options_fuzzer_LDADD = ../src/gpgme.o
else
  wget_options_fuzzer_LDADD =
endif
wget_options_fuzzer_LDADD += \
 ../src/options.o \
 ../src/log.o \
 ../src/stats_server.o \
 ../src/stats_site.o \
 ../src/utils.o \
 ../src/dl.o \
 ../src/plugin.o \
 ../src/testing.o \
 $(LDADD)


EXTRA_DIST = valgrind-suppressions
#EXTRA_DIST = $(wildcard *.options) $(wildcard *.dict) \
# $(wildcard *.in) $(wildcard *.repro)

dist-hook:
	find $(srcdir) -name '*.options' -exec cp -v '{}' $(distdir) ';'
	find $(srcdir) -name '*.dict' -exec cp -v '{}' $(distdir) ';'
#	find $(srcdir) -name '*.in' -exec cp -vr '{}' $(distdir) ';'
	find $(srcdir) -name '*.repro' -exec cp -vr '{}' $(distdir) ';'

clean-local:
	rm -rf *.gc?? *.log lcov

oss-fuzz:
	if test "$$OUT" != ""; then \
	XLIBS="-lpsl -lgnutls -lhogweed -lnettle -lgmp -lidn2 -lunistring -lz"; \
	for ccfile in libwget*_fuzzer.c; do \
	fuzzer=$$(basename $$ccfile .c); \
	$$CXX $$CXXFLAGS -I$(top_srcdir)/include/wget/ -I$(top_srcdir) \
	"$${fuzzer}.c" -o "$${fuzzer}" \
	../libwget/.libs/libwget.a $${LIB_FUZZING_ENGINE} \
	-Wl,-Bstatic $${XLIBS} -Wl,-Bdynamic -lgnutls; \
	done; \
	for ccfile in wget*_fuzzer.c; do \
	fuzzer=$$(basename $$ccfile .c); \
	$$CXX $$CXXFLAGS -I$(top_srcdir)/include/wget/ -I$(top_srcdir) \
	"$${fuzzer}.c" -o "$${fuzzer}" \
	../src/options.o ../src/log.o \
	../src/stats_server.o ../src/stats_site.o ../src/utils.o ../src/dl.o ../src/plugin.o ../src/testing.o \
	../libwget/.libs/libwget.a $${LIB_FUZZING_ENGINE} \
	-Wl,-Bstatic $${XLIBS} -Wl,-Bdynamic -lgnutls; \
	done; \
	fi

.PHONY: oss-fuzz

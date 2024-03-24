AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(MANYWARNINGS) -DBUILDING_LIBWGET

# $(ALL_LIBS) is set to $LIBS in configure.ac
LIBS =

libwget_libadd = ../lib/libgnu.la $(CODE_COVERAGE_LIBS) \
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
 $(ALL_LIBS)

lib_LTLIBRARIES = libwget.la

libwget_la_SOURCES = \
 atom_url.c bar.c bitmap.c buffer.c buffer_printf.c base64.c console.c cookie.c cookie.h cookie_parse.c css.c css_tokenizer.h css_url.c \
 decompressor.c dns_cache.c encoding.c hash_printf.c hashfile.c hashmap.c io.c hsts.c hpkp.c hpkp.h hpkp_db.c html_url.c http.c http.h \
 http_parse.c  init.c ip.c iri.c list.c log.c logger.c logger.h mem.c metalink.c net.c net.h netrc.c ocsp.c pipe.c \
 plugin.c printf.c random.c robots.c rss_url.c sitemap_url.c stringmap.c strlcpy.c \
 strscpy.c thread.c tls_session.c utils.c vector.c xalloc.c xml.c private.h http_highlevel.c error.c dns.c

if WITH_LIBNGHTTP2
  libwget_la_SOURCES += http2.c
endif

if WITH_GNUTLS
  libwget_la_SOURCES += ssl_gnutls.c ssl.c
else
if WITH_OPENSSL
  libwget_la_SOURCES += ssl_openssl.c ssl.c
else
if WITH_WOLFSSL
  libwget_la_SOURCES += ssl_wolfssl.c ssl.c
else
  libwget_la_SOURCES += ssl_none.c
endif
endif
endif

libwget_la_CPPFLAGS =\
 -fPIC -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib $(CFLAG_VISIBILITY) -DBUILDING_LIBWGET \
 $(CODE_COVERAGE_CPPFLAGS) \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
libwget_la_LIBADD = libcsstokenizer.la $(libwget_libadd)

# include ABI version information
libwget_la_LDFLAGS = -no-undefined -version-info $(LIBWGET_SO_VERSION)

# convenience library to avoid warnings about unused macros
noinst_LTLIBRARIES = libcsstokenizer.la
libcsstokenizer_la_SOURCES = css_tokenizer.c css_tokenizer.lex
libcsstokenizer_la_CFLAGS = $(AM_CFLAGS)
libcsstokenizer_la_CPPFLAGS = $(libwget_la_CPPFLAGS)

# gnulib needs config.h included before any gnulib header files
css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	$(AM_V_GEN)
	$(AM_V_at)$(LEX) -w -o $@ $(srcdir)/css_tokenizer.lex
	$(AM_V_at)$(SED) 's/fprintf/wget_fprintf/g' $@ >$@.tmp
	$(AM_V_at)mv $@.tmp $@
	$(AM_V_at)rm -f lex.yy.c

DISTCLEANFILES = css_tokenizer.c

if ENABLE_MANYLIBS

######## libwget alloc ########
lib_LTLIBRARIES += libwget_alloc.la
libwget_alloc_la_SOURCES = xalloc.c
libwget_alloc_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_alloc_la_LIBADD = $(libwget_libadd)
libwget_alloc_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget ip ########
lib_LTLIBRARIES += libwget_ip.la
libwget_ip_la_SOURCES =  ip.c
libwget_ip_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_ip_la_LIBADD = $(libwget_libadd)
libwget_ip_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget common ########
lib_LTLIBRARIES += libwget_common.la
libwget_common_la_SOURCES = buffer.c buffer_printf.c base64.c bitmap.c hashmap.c list.c log.c mem.c printf.c stringmap.c strlcpy.c strscpy.c utils.c vector.c error.c
libwget_common_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_common_la_LIBADD = libwget_alloc.la $(libwget_libadd)
libwget_common_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget thread ########
lib_LTLIBRARIES += libwget_thread.la
libwget_thread_la_SOURCES = thread.c
libwget_thread_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_thread_la_LIBADD = libwget_alloc.la $(libwget_libadd)
libwget_thread_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget encoding ########
lib_LTLIBRARIES += libwget_encoding.la
libwget_encoding_la_SOURCES = encoding.c
libwget_encoding_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_encoding_la_LIBADD = libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_encoding_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget iri ########
lib_LTLIBRARIES += libwget_iri.la
libwget_iri_la_SOURCES = iri.c
libwget_iri_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_iri_la_LIBADD = libwget_encoding.la libwget_ip.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_iri_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget io ########
lib_LTLIBRARIES += libwget_io.la
libwget_io_la_SOURCES = io.c
libwget_io_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_io_la_LIBADD = libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_io_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget hashfile ########
lib_LTLIBRARIES += libwget_hashfile.la
libwget_hashfile_la_SOURCES = hashfile.c
libwget_hashfile_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_hashfile_la_LIBADD = libwget_common.la libwget_alloc.la $(libwget_libadd) $(GNUTLS_LIBS) $(WOLFSSL_LIBS) $(OPENSSL_LIBS) $(NETTLE_LIBS)
libwget_hashfile_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget hpkp_db ########
lib_LTLIBRARIES += libwget_hpkp_db.la
libwget_hpkp_db_la_SOURCES = hpkp_db.c hpkp.c hpkp.h
libwget_hpkp_db_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_hpkp_db_la_LIBADD = libwget_hashfile.la libwget_io.la libwget_thread.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_hpkp_db_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget hsts ########
lib_LTLIBRARIES += libwget_hsts.la
libwget_hsts_la_SOURCES = hsts.c
libwget_hsts_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_hsts_la_LIBADD = libwget_ip.la libwget_io.la libwget_thread.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_hsts_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget ocsp ########
lib_LTLIBRARIES += libwget_ocsp.la
libwget_ocsp_la_SOURCES = ocsp.c
libwget_ocsp_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_ocsp_la_LIBADD = libwget_io.la libwget_thread.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_ocsp_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget tls_session ########
lib_LTLIBRARIES += libwget_tls_session.la
libwget_tls_session_la_SOURCES = tls_session.c
libwget_tls_session_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_tls_session_la_LIBADD = libwget_io.la libwget_thread.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_tls_session_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget http_parse ########
lib_LTLIBRARIES += libwget_http_parse.la
libwget_http_parse_la_SOURCES = http_parse.c cookie_parse.c cookie.h hpkp.c cookie.h
libwget_http_parse_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_http_parse_la_LIBADD = libwget_encoding.la libwget_common.la libwget_alloc.la $(libwget_libadd) $(LIBPSL_LIBS)
libwget_http_parse_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget logger ########
lib_LTLIBRARIES += libwget_logger.la
libwget_logger_la_SOURCES = logger.c
libwget_logger_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_logger_la_LIBADD = libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_logger_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget dnscache ########
lib_LTLIBRARIES += libwget_dnscache.la
libwget_dnscache_la_SOURCES = dns_cache.c
libwget_dnscache_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_dnscache_la_LIBADD = libwget_ip.la libwget_thread.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_dnscache_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget dns ########
lib_LTLIBRARIES += libwget_dns.la
libwget_dns_la_SOURCES = dns.c
libwget_dns_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_dns_la_LIBADD = libwget_dnscache.la libwget_ip.la libwget_logger.la libwget_thread.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_dns_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget robots ########
lib_LTLIBRARIES += libwget_robots.la
libwget_robots_la_SOURCES = robots.c
libwget_robots_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_robots_la_LIBADD = libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_robots_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget xml ########
lib_LTLIBRARIES += libwget_xml.la
libwget_xml_la_SOURCES = xml.c
libwget_xml_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_xml_la_LIBADD = libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_xml_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget metalink ########
lib_LTLIBRARIES += libwget_metalink.la
libwget_metalink_la_SOURCES = metalink.c
libwget_metalink_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_metalink_la_LIBADD = libwget_xml.la libwget_iri.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_metalink_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget netrc ########
lib_LTLIBRARIES += libwget_netrc.la
libwget_netrc_la_SOURCES = netrc.c
libwget_netrc_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_netrc_la_LIBADD = libwget_io.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_netrc_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget decompress ########
lib_LTLIBRARIES += libwget_decompress.la
libwget_decompress_la_SOURCES = decompressor.c
libwget_decompress_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_decompress_la_LIBADD = libwget_common.la libwget_alloc.la $(libwget_libadd) $(ZSTD_LIBS) $(BROTLIDEC_LIBS) $(LZMA_LIBS) $(ZLIB_LIBS) $(BZ2_LIBS) $(LZIP_LIBS)
libwget_decompress_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget CSS ########
lib_LTLIBRARIES += libwget_css.la
libwget_css_la_SOURCES = css_url.c css.c css_tokenizer.h
libwget_css_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_css_la_LIBADD = libcsstokenizer.la  libwget_iri.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_css_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## libwget progress ########
lib_LTLIBRARIES += libwget_progress.la
libwget_progress_la_SOURCES = bar.c
libwget_progress_la_CPPFLAGS = $(libwget_la_CPPFLAGS)
libwget_progress_la_LIBADD = libwget_thread.la libwget_common.la libwget_alloc.la $(libwget_libadd)
libwget_progress_la_LDFLAGS = $(libwget_la_LDFLAGS)

######## Test linking ########
noinst_PROGRAMS = test_linking_common
test_linking_common_SOURCES = test_linking_common.c
test_linking_common_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_common_LDADD = libwget_common.la
test_linking_common_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_encoding
test_linking_encoding_SOURCES = test_linking_encoding.c
test_linking_encoding_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_encoding_LDADD = libwget_encoding.la
test_linking_encoding_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_iri
test_linking_iri_SOURCES = test_linking_iri.c
test_linking_iri_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_iri_LDADD = libwget_iri.la
test_linking_iri_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_io
test_linking_io_SOURCES = test_linking_io.c
test_linking_io_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_io_LDADD = libwget_io.la
test_linking_io_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_hashfile
test_linking_hashfile_SOURCES = test_linking_hashfile.c
test_linking_hashfile_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_hashfile_LDADD = libwget_hashfile.la
test_linking_hashfile_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_hpkp_db
test_linking_hpkp_db_SOURCES = test_linking_hpkp_db.c
test_linking_hpkp_db_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_hpkp_db_LDADD = libwget_hpkp_db.la
test_linking_hpkp_db_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_hsts
test_linking_hsts_SOURCES = test_linking_hsts.c
test_linking_hsts_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_hsts_LDADD = libwget_hsts.la
test_linking_hsts_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_ocsp
test_linking_ocsp_SOURCES = test_linking_ocsp.c
test_linking_ocsp_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_ocsp_LDADD = libwget_ocsp.la
test_linking_ocsp_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_tls_session
test_linking_tls_session_SOURCES = test_linking_tls_session.c
test_linking_tls_session_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_tls_session_LDADD = libwget_tls_session.la
test_linking_tls_session_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_http_parse
test_linking_http_parse_SOURCES = test_linking_http_parse.c
test_linking_http_parse_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_http_parse_LDADD = libwget_http_parse.la
test_linking_http_parse_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_logger
test_linking_logger_SOURCES = test_linking_logger.c
test_linking_logger_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_logger_LDADD = libwget_logger.la
test_linking_logger_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_css
test_linking_css_SOURCES = test_linking_css.c
test_linking_css_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_css_LDADD = libwget_css.la
test_linking_css_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_progress
test_linking_progress_SOURCES = test_linking_progress.c
test_linking_progress_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_progress_LDADD = libwget_progress.la
test_linking_progress_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_thread
test_linking_thread_SOURCES = test_linking_thread.c
test_linking_thread_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_thread_LDADD = libwget_thread.la
test_linking_thread_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_dnscache
test_linking_dnscache_SOURCES = test_linking_dnscache.c
test_linking_dnscache_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_dnscache_LDADD = libwget_dnscache.la
test_linking_dnscache_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_dns
test_linking_dns_SOURCES = test_linking_dns.c
test_linking_dns_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_dns_LDADD = libwget_dns.la
test_linking_dns_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_robots
test_linking_robots_SOURCES = test_linking_robots.c
test_linking_robots_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_robots_LDADD = libwget_robots.la
test_linking_robots_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_xml
test_linking_xml_SOURCES = test_linking_xml.c
test_linking_xml_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_xml_LDADD = libwget_xml.la
test_linking_xml_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_metalink
test_linking_metalink_SOURCES = test_linking_metalink.c
test_linking_metalink_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_metalink_LDADD = libwget_metalink.la
test_linking_metalink_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_netrc
test_linking_netrc_SOURCES = test_linking_netrc.c
test_linking_netrc_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_netrc_LDADD = libwget_netrc.la
test_linking_netrc_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking_decompress
test_linking_decompress_SOURCES = test_linking_decompress.c
test_linking_decompress_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_decompress_LDADD = libwget_decompress.la
test_linking_decompress_LDFLAGS = -static -no-install

noinst_PROGRAMS += test_linking
test_linking_SOURCES = test_linking.c
test_linking_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(top_builddir)/include/wget
test_linking_LDADD = libwget.la
test_linking_LDFLAGS = -static -no-install

endif # ENABLE_MANYLIBS

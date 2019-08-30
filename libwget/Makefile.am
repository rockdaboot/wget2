AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(MANYWARNINGS) -DBUILDING_LIBWGET

lib_LTLIBRARIES = libwget.la

libwget_la_SOURCES = \
 atom_url.c bar.c bitmap.c buffer.c buffer_printf.c base64.c console.c cookie.c cookie.h cookie_parse.c css.c css_tokenizer.h css_url.c \
 decompressor.c dns_cache.c encoding.c hash_printf.c hashfile.c hashmap.c io.c hsts.c hpkp.c hpkp.h hpkp_db.c html_url.c http.c http.h \
 http_parse.c  init.c ip.c iri.c list.c log.c logger.c logger.h mem.c metalink.c net.c net.h netrc.c ocsp.c pipe.c \
 plugin.c printf.c random.c robots.c rss_url.c sitemap_url.c stringmap.c strlcpy.c \
 strscpy.c thread.c tls_session.c utils.c vector.c xalloc.c xml.c private.h http_highlevel.c error.c dns.c

if WITH_GNUTLS
  libwget_la_SOURCES += ssl_gnutls.c
else
if WITH_OPENSSL
  libwget_la_SOURCES += ssl_openssl.c
else
if WITH_WOLFSSL
  libwget_la_SOURCES += ssl_wolfssl.c
else
  libwget_la_SOURCES += ssl_none.c
endif
endif
endif

libwget_la_CPPFLAGS =\
 -fPIC -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib $(CFLAG_VISIBILITY) -DBUILDING_LIBWGET \
 $(CODE_COVERAGE_CPPFLAGS) \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
libwget_la_LIBADD =\
 $(LIBOBJS) libcsstokenizer.la $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB) $(INET_PTON_LIB) \
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_CRYPTO) $(LIB_GETLOGIN) $(LIB_NANOSLEEP) $(LIB_POLL) \
 $(LIB_POSIX_SPAWN) $(LIB_PTHREAD_SIGMASK) $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) \
 $(LTLIBMULTITHREAD) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@ \
 $(LIBS) ../lib/libgnu.la $(CODE_COVERAGE_LIBS)

# include ABI version information
libwget_la_LDFLAGS = -no-undefined -version-info $(LIBWGET_SO_VERSION)

# convenience library to avoid warnings about unused macros
noinst_LTLIBRARIES = libcsstokenizer.la
libcsstokenizer_la_SOURCES = css_tokenizer.c css_tokenizer.lex
libcsstokenizer_la_CFLAGS = $(AM_CFLAGS)
libcsstokenizer_la_CPPFLAGS = $(libwget_la_CPPFLAGS)

noinst_PROGRAMS = test_linking
test_linking_SOURCES = test_linking.c
test_linking_LDFLAGS = -static
test_linking_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
test_linking_LDADD = libwget.la ../lib/libgnu.la

# gnulib needs config.h included before any gnulib header files
css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	$(AM_V_GEN)
	$(AM_V_at)$(LEX) -w -o $@ $(srcdir)/css_tokenizer.lex
	$(AM_V_at)$(SED) 's/fprintf/wget_fprintf/g' $@ >$@.tmp
	$(AM_V_at)mv $@.tmp $@
	$(AM_V_at)rm -f lex.yy.c

DISTCLEANFILES = css_tokenizer.c

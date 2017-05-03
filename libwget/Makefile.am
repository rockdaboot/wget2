AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)

lib_LTLIBRARIES = libwget.la
libwget_la_SOURCES = \
 atom_url.c bar.c buffer.c buffer_printf.c base64.c console.c cookie.c\
 css.c css_tokenizer.c css_tokenizer.h css_tokenizer.lex css_url.c\
 decompressor.c encoding.c hashfile.c hashmap.c io.c hsts.c hpkp.c html_url.c http.c http.h init.c ip.c iri.c\
 list.c log.c logger.c logger.h md5.c mem.c metalink.c net.c net.h netrc.c ocsp.c pipe.c printf.c random.c \
 robots.c rss_url.c sitemap_url.c ssl_gnutls.c stringmap.c strlcpy.c thread.c tls_session.c utils.c \
 vector.c xalloc.c xml.c private.h http_highlevel.c
libwget_la_CPPFLAGS =\
 -fPIC -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib $(CFLAG_VISIBILITY) -DBUILDING_LIBWGET \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
libwget_la_LIBADD =\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB) $(INET_PTON_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_CRYPTO) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

# include ABI version information
libwget_la_LDFLAGS = -no-undefined -version-info $(LIBWGET_SO_VERSION)

noinst_PROGRAMS = test_linking
test_linking_SOURCES = test_linking.c
test_linking_LDFLAGS = -static
test_linking_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
test_linking_LDADD = libwget.la ../lib/libgnu.la

# gnulib needs config.h included before any gnulib header files
css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	@(echo '#include "config.h"'; $(LEX) -w -t $(srcdir)/css_tokenizer.lex) >$@

clean-local:
	-rm -f css_tokenizer.c

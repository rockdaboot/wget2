LDADD = $(LIBOBJS) $(LIBSOCKET) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_SELECT) $(LTLIBINTL) ../lib/libgnu.a
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib

lib_LTLIBRARIES = libwget.la
libwget_la_SOURCES = \
 atom_url.c bar.c buffer.c buffer_printf.c base64.c compat.c cookie.c\
 css.c css_tokenizer.c css_tokenizer.h css_tokenizer.lex css_url.c\
 decompressor.c encoding.c hashfile.c hashmap.c io.c hsts.c html_url.c http.c init.c iri.c\
 list.c log.c logger.c md5.c mem.c metalink.c net.c net.h netrc.c ocsp.c pipe.c\
 robots.c rss_url.c sitemap_url.c ssl_gnutls.c stringmap.c thread.c utils.c vector.c xalloc.c\
 xml.c private.h http_highlevel.c

#libwget_la_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir)

# include ABI version information
libwget_la_LDFLAGS = -version-info $(LIBWGET_SO_VERSION)

#bin_PROGRAMS = test_linking
noinst_PROGRAMS = test_linking
test_linking_SOURCES = test_linking.c
test_linking_LDADD = libwget.la @LTLIBICONV@ $(LIBOBJS) $(LIBSOCKET) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_SELECT) $(LIBINTL) $(LIBS) ../lib/libgnu.a
test_linking_LDFLAGS = -static

css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	@$(LEX) -w -o$@ $(srcdir)/css_tokenizer.lex

clean-local:
	-rm -f css_tokenizer.c

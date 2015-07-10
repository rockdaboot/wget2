lib_LTLIBRARIES = libmget-@LIBMGET_API_VERSION@.la
libmget_@LIBMGET_API_VERSION@_la_SOURCES = \
 atom_url.c bar.c buffer.c buffer_printf.c base64.c compat.c cookie.c\
 css.c css_tokenizer.c css_tokenizer.h css_tokenizer.lex css_url.c\
 decompressor.c encoding.c hashfile.c hashmap.c io.c hsts.c html_url.c http.c init.c iri.c\
 list.c log.c logger.c md5.c mem.c metalink.c net.c net.h ocsp.c pipe.c printf.c robots.c\
 rss_url.c sitemap_url.c ssl_gnutls.c stringmap.c thread.c utils.c vector.c xalloc.c xml.c\
 private.h http_highlevel.c

libmget_@LIBMGET_API_VERSION@_la_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir)

# include ABI version information
libmget_@LIBMGET_API_VERSION@_la_LDFLAGS = -version-info $(LIBMGET_SO_VERSION)

#bin_PROGRAMS = test_linking
noinst_PROGRAMS = test_linking
test_linking_SOURCES = test_linking.c
test_linking_CPPFLAGS = -I$(top_srcdir)/include
test_linking_LDADD = libmget-@LIBMGET_API_VERSION@.la @LTLIBICONV@ @LTLIBINTL@ $(LIBS)
test_linking_LDFLAGS = -static

css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	@$(LEX) -w -o $@ $(srcdir)/css_tokenizer.lex

clean-local:
	-rm -f css_tokenizer.c

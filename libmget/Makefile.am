lib_LTLIBRARIES = libmget.la
libmget_la_SOURCES = atom_url.c buffer.c buffer_printf.c base64.c compat.c cookie.c\
 css.c css_tokenizer.c css_tokenizer.h css_tokenizer.lex css_url.c\
 decompressor.c encoding.c hashfile.c hashmap.c io.c html_url.c http.c init.c iri.c\
 list.c log.c logger.c md5.c mem.c metalink.c net.c pipe.c printf.c robots.c sitemap_url.c ssl_gnutls.c\
 stringmap.c thread.c utils.c vector.c xalloc.c xml.c private.h http_highlevel.c

libmget_la_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

bin_PROGRAMS = test_linking
test_linking_SOURCES = test_linking.c
test_linking_CPPFLAGS = -I$(top_srcdir)/include
test_linking_LDADD = ../libmget/libmget.la
test_linking_LDFLAGS = -static

css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	$(LEX) -o $@ $<

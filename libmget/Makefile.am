lib_LTLIBRARIES = libmget.la
libmget_la_SOURCES = buffer.c buffer_printf.c base64.c compat.c cookie.c\
 css.c css_tokenizer.c css_tokenizer.h css_tokenizer.lex css_url.c \
 decompressor.c hashmap.c io.c iri.c list.c log.c logger.c mem.c net.c pipe.c\
 printf.c ssl_gnutls.c stringmap.c utils.c vector.c xalloc.c xml.c private.h

libmget_la_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

bin_PROGRAMS = test_linking
test_linking_SOURCES = test_linking.c
test_linking_CPPFLAGS = -I$(top_srcdir)/include
test_linking_LDADD = ../libmget/libmget.la
test_linking_LDFLAGS = -static

css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	$(LEX) -o $@ $<

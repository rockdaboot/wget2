DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/@PACKAGE@\" -DLOCALEDIR=\"$(localedir)\"

bin_PROGRAMS = mget
mget_SOURCES = base64.c base64.h blacklist.c blacklist.h buffer.c buffer.h\
 buffer_printf.c cookie.c cookie.h css.c css.h css_tokenizer.c css_tokenizer.h\
 decompressor.c decompressor.h hash.c hash.h hashmap.c hashmap.h http.c http.h\
 iri.c iri.h job.c job.h log.c log.h md5.c md5.h metalink.c metalink.h mget.c\
 net.c net.h options.c options.h printf.c printf.h ssl_gnutls.c\
 stringmap.c stringmap.h ssl.h utf8.c utf8.h utils.c utils.h vector.c vector.h\
 xalloc.c xalloc.h xml.c xml.h
mget_CPPFLAGS = -I$(top_srcdir)/include
mget_LDADD = ../libmget/libmget.la

css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	$(LEX) -o $@ $<

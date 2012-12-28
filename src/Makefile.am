DEFS         = @DEFS@ -DSYSTEM_MGETRC=\"$(sysconfdir)/mgetrc\" -DLOCALEDIR=\"$(localedir)\"

bin_PROGRAMS = mget
mget_SOURCES = base64.c blacklist.c buffer.c buffer_printf.c cookie.c\
 css.c css_tokenizer.c decompressor.c hash.c hashmap.c http.c iri.c job.c\
 log.c md5.c metalink.c mget.c net.c options.c printf.c ssl_gnutls.c\
 stringmap.c utf8.c utils.c vector.c xalloc.c xml.c
mget_CPPFLAGS = -I$(top_srcdir)/include
mget_LDADD = ../libmget/libmget.la

css_tokenizer.c: css_tokenizer.lex css_tokenizer.h
	$(LEX) -o $@ $<

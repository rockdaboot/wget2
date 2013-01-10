DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/@PACKAGE@\" -DLOCALEDIR=\"$(localedir)\"

bin_PROGRAMS = mget x
mget_SOURCES = blacklist.c blacklist.h \
 cookie.c cookie.h css.c css.h css_tokenizer.c css_tokenizer.h\
 hash.c hash.h http.c http.h\
 iri.c iri.h job.c job.h log.c log.h md5.c md5.h metalink.c metalink.h mget.c\
 net.c net.h options.c options.h printf.c printf.h ssl_gnutls.c\
 ssl.h utf8.c utf8.h utils.c utils.h\
 xml.c xml.h
mget_CPPFLAGS = -I$(top_srcdir)/include
mget_LDADD = ../libmget/libmget.la
mget_LDFLAGS = -static

x_SOURCES = x.c
x_CPPFLAGS = -I$(top_srcdir)/include
x_LDADD = ../libmget/libmget.la
x_LDFLAGS = -static

css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
	$(LEX) -o $@ $<

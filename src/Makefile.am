DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/@PACKAGE@\" -DLOCALEDIR=\"$(localedir)\"

bin_PROGRAMS = mget
mget_SOURCES = blacklist.c blacklist.h \
 hash.c hash.h http.c http.h\
 job.c job.h log.c log.h md5.c md5.h metalink.c metalink.h mget.c mget.h\
 options.c options.h
mget_CPPFLAGS = -I$(top_srcdir)/include
mget_LDADD = ../libmget/libmget.la
mget_LDFLAGS = -static

#x_SOURCES = test_linking.c
#x_CPPFLAGS = -I$(top_srcdir)/include
#x_LDADD = ../libmget/libmget.la
#x_LDFLAGS = -static

#css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
#	$(LEX) -o $@ $<

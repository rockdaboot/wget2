DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/@PACKAGE@\" -DLOCALEDIR=\"$(localedir)\"

bin_PROGRAMS = mget
mget_SOURCES = bar.c bar.h blacklist.c blacklist.h host.c host.h job.c job.h log.c log.h\
 mget.c mget.h options.c options.h
mget_CPPFLAGS = -I$(top_srcdir)/include
mget_LDADD = ../libmget/libmget-@LIBMGET_API_VERSION@.la @LTLIBICONV@ @LTLIBINTL@
mget_LDFLAGS = -static

#x_SOURCES = test_linking.c
#x_CPPFLAGS = -I$(top_srcdir)/include
#x_LDADD = ../libmget/libmget.la
#x_LDFLAGS = -static

#css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
#	$(LEX) -o $@ $<

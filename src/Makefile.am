DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/@PACKAGE@\" -DLOCALEDIR=\"$(localedir)\"

LDADD = $(LIBOBJS) ../lib/libgnu.a
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib

bin_PROGRAMS = wget2
wget2_SOURCES = bar.c bar.h blacklist.c blacklist.h host.c host.h job.c job.h log.c log.h\
 wget.c wget.h options.c options.h
wget2_LDADD = ../libwget/libwget.la @LTLIBICONV@ @LTLIBINTL@ $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_SELECT) ../lib/libgnu.a
wget2_LDFLAGS = -static

#x_SOURCES = test_linking.c
#x_CPPFLAGS = -I$(top_srcdir)/include
#x_LDADD = ../libwget/libwget.la
#x_LDFLAGS = -static

#css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
#	$(LEX) -o $@ $<

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\" -DLOCALEDIR=\"$(localedir)\"

LDADD = $(LIBOBJS) ../lib/libgnu.a
AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" \
 -DWGET_PLUGIN_DIR=\"$(libdir)/wget2/plugins\"

bin_PROGRAMS = wget2 wget2_noinstall

wget2_SOURCES =\
 bar.c wget_bar.h\
 blacklist.c wget_blacklist.h\
 dl.c wget_dl.h\
 host.c wget_host.h\
 job.c wget_job.h\
 log.c wget_log.h\
 plugin.c wget_plugin.h\
 stats.c stats_dns.c stats_tls.c stats_ocsp.c stats_server.c stats_site.c wget_stats.h\
 wget.c wget_main.h\
 options.c wget_options.h\
 testing.c wget_testing.h\
 wget_xattr.h \
 utils.c wget_utils.h \
 version-text.h

if WITH_GPGME
  wget2_SOURCES += gpgme.c wget_gpgme.h
endif

wget2_LDADD = ../libwget/libwget.la \
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB) $(INET_PTON_LIB) \
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_CRYPTO) $(LIB_GETLOGIN) $(LIB_NANOSLEEP) $(LIB_POLL) \
 $(LIB_POSIX_SPAWN) $(LIB_PTHREAD_SIGMASK) $(LIB_SELECT) $(LTLIBICONV) $(LTLIBINTL) \
 $(LTLIBMULTITHREAD) $(LTLIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@ \
 $(LIBS) ../lib/libgnu.la

wget2_noinstall_SOURCES = $(wget2_SOURCES)
wget2_noinstall_LDFLAGS = -no-install
wget2_noinstall_LDADD = $(wget2_LDADD)

#css_tokenizer.c: $(srcdir)/css_tokenizer.lex css_tokenizer.h
#	$(LEX) -o $@ $<

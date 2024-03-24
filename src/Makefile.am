DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\" -DLOCALEDIR=\"$(localedir)\"

LDADD = $(CODE_COVERAGE_LIBS) $(LIBOBJS) ../lib/libgnu.a
AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) $(CODE_COVERAGE_CFLAGS) -DMALLOC_RETURNS_NONNULL
AM_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 $(CODE_COVERAGE_CPPLAGS) \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" \
 -DWGET_PLUGIN_DIR=\"$(libdir)/wget2/plugins\" \
 -DMALLOC_RETURNS_NONNULL

bin_PROGRAMS = wget2 wget2_noinstall

wget2_SOURCES =\
 bar.c wget_bar.h\
 blacklist.c wget_blacklist.h\
 dl.c wget_dl.h\
 host.c wget_host.h\
 job.c wget_job.h\
 log.c wget_log.h\
 plugin.c wget_plugin.h\
 stats_server.c stats_site.c wget_stats.h\
 wget.c wget_main.h\
 options.c wget_options.h\
 testing.c wget_testing.h\
 wget_xattr.h \
 utils.c wget_utils.h

if WITH_GPGME
  wget2_SOURCES += gpgme.c wget_gpgme.h
endif

wget2_LDADD = ../lib/libgnu.la ../libwget/libwget.la $(LIBOBJS) \
 $(CLOCK_TIME_LIB) \
 $(GETADDRINFO_LIB) \
 $(GETHOSTNAME_LIB) \
 $(GETLOGIN_LIB) \
 $(GETRANDOM_LIB) \
 $(HARD_LOCALE_LIB) \
 $(HOSTENT_LIB) \
 $(INET_NTOP_LIB) \
 $(INET_PTON_LIB) \
 $(LIBMULTITHREAD) \
 $(LIBSOCKET) \
 $(LIBTHREAD) \
 $(LIB_CRYPTO) \
 $(LTLIBC32CONV) \
 $(LTLIBICONV) \
 $(LTLIBINTL) \
 $(LTLIBUNISTRING) \
 $(MBRTOWC_LIB) \
 $(NANOSLEEP_LIB) \
 $(POLL_LIB) \
 $(POSIX_SPAWN_LIB) \
 $(PTHREAD_SIGMASK_LIB) \
 $(SELECT_LIB) \
 $(SERVENT_LIB) \
 $(SETLOCALE_LIB) \
 $(SETLOCALE_NULL_LIB) \
 @INTL_MACOSX_LIBS@ \
 $(LIBS)

wget2_noinstall_SOURCES = $(wget2_SOURCES)
wget2_noinstall_LDFLAGS = -no-install
wget2_noinstall_LDADD = $(wget2_LDADD)

# convenience library used for testing
noinst_LTLIBRARIES = libtest-utils.la
libtest_utils_la_SOURCES = utils.c wget_utils.h
libtest_utils_la_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include/wget -I$(top_builddir)/lib -I$(top_srcdir)/lib $(CFLAG_VISIBILITY) -DBUILDING_LIBWGET \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"

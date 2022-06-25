noinst_PROGRAMS = \
 batch_loader\
 getstream\
 http_get2\
 http_multi_get\
 print_css_urls\
 print_css_urls2\
 print_css_urls3 http_get\
 print_html_urls\
 websequencediagram\
 websequencediagram_high\
 check_url_types\
 relative_to_absolute_url


AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) -DMALLOC_RETURNS_NONNULL
AM_CPPFLAGS = -I$(top_srcdir)/include/wget \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" -DMALLOC_RETURNS_NONNULL
AM_LDFLAGS = -no-install
LDADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(GETHOSTNAME_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB) $(INET_PTON_LIB) \
 $(LIBMULTITHREAD) $(LIBSOCKET) $(LIBTHREAD) $(LIB_CLOCK_GETTIME) $(LIB_CRYPTO) $(LIB_GETLOGIN) \
 $(LIB_HARD_LOCALE) $(LIB_MBRTOWC) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_POSIX_SPAWN) $(LIB_PTHREAD_SIGMASK) \
 $(LIB_SELECT) $(LIB_SETLOCALE) $(LIB_SETLOCALE_NULL) $(LTLIBICONV) $(LTLIBINTL) $(SERVENT_LIB) @INTL_MACOSX_LIBS@ \
 $(LIBS)

noinst_PROGRAMS = print_css_urls print_css_urls2 print_css_urls3 http_get\
 http_get2 getstream print_html_urls websequencediagram websequencediagram_high

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib
AM_LDFLAGS = -no-install
LDADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL) $(LIB_PTHREAD)\
 $(LIB_SELECT) $(LIBICONV) $(LIBINTL) $(LIBTHREAD) $(SERVENT_LIB) @INTL_MACOSX_LIBS@\
 $(LIBS) ../lib/libgnu.la

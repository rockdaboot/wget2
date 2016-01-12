noinst_PROGRAMS = print_css_urls print_css_urls2 print_css_urls3 http_get\
 http_get2 getstream print_html_urls

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib
AM_LDFLAGS = -static
LDADD = ../libwget/libwget.la\
 $(LIBOBJS) $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB)\
 $(LIBSOCKET) $(LIB_CLOCK_GETTIME) $(LIB_NANOSLEEP) $(LIB_POLL)\
 $(LIB_SELECT) $(LIBICONV) $(LIBINTL) $(SERVENT_LIB) $(LIBS) ../lib/libgnu.a

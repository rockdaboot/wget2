bin_PROGRAMS = print_css_urls print_css_urls2 print_css_urls3 http_get

INCLUDES = -I$(top_srcdir)/include
AM_LDFLAGS = -static
local_ldadd = $(top_srcdir)/libmget/libmget.la

print_css_urls_SOURCES = print_css_urls.c
print_css_urls_LDADD = $(local_ldadd)

print_css_urls2_SOURCES = print_css_urls2.c
print_css_urls2_LDADD = $(local_ldadd)

print_css_urls3_SOURCES = print_css_urls3.c
print_css_urls3_LDADD = $(local_ldadd)

http_get_SOURCES = http_get.c
http_get_LDADD = ../src/mget-http.o ../src/mget-md5.o $(local_ldadd)

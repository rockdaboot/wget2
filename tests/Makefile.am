#DEFS = @DEFS@ -DDATADIR=\"$(datadir)/@PACKAGE@\" -DSRCDIR=\"$(srcdir)\"
DEFS = @DEFS@ -DDATADIR=\"$(top_srcdir)/data\" -DSRCDIR=\"$(srcdir)\"


check_PROGRAMS = test buffer_printf2_perf stringmap_perf

test_SOURCES = test.c
test_CPPFLAGS = -I$(top_srcdir)/include
test_LDADD = ../libmget/libmget.la ../src/mget-xalloc.o ../src/mget-printf.o\
 ../src/mget-buffer.o ../src/mget-buffer_printf.o ../src/mget-stringmap.o\
 ../src/mget-log.o ../src/mget-http.o ../src/mget-iri.o ../src/mget-utils.o\
 ../src/mget-vector.o ../src/mget-css.o ../src/mget-hashmap.o\
 ../src/mget-cookie.o ../src/mget-options.o ../src/mget-net.o\
 ../src/mget-decompressor.o ../src/mget-css_tokenizer.o ../src/mget-md5.o\
 ../src/mget-xml.o ../src/mget-base64.o ../src/mget-utf8.o\
 ../src/mget-ssl_gnutls.o

buffer_printf2_perf_SOURCES = buffer_printf2_perf.c
buffer_printf2_perf_CPPFLAGS = -I$(top_srcdir)/include
buffer_printf2_perf_LDADD = ../libmget/libmget.la ../src/mget-buffer.o\
 ../src/mget-buffer_printf.o ../src/mget-log.o ../src/mget-xalloc.o

stringmap_perf_SOURCES = stringmap_perf.c
stringmap_perf_CPPFLAGS = -I$(top_srcdir)/include
stringmap_perf_LDADD = ../libmget/libmget.la ../src/mget-stringmap.o\
 ../src/mget-hashmap.o ../src/mget-xalloc.o ../src/mget-log.o

EXTRA_DIST = files
dist-hook:
	rm -f $(distdir)/files/elb_bibel.txt
#	cp $(top_srcdir)/data/public_suffixes.txt $(distdir)/files/
#	rm -rf `find $(distdir)/files -name CVS`

#dist-hook:
#	mkdir $(distdir)/random
#	cp -p $(srcdir)/random/a1 $(srcdir)/random/a2 $(distdir)/random

TESTS = test

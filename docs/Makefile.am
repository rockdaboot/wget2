EXTRA_DIST = DoxygenLayout.xml

man3_MANS =\
 $(builddir)/man/man3/libwget-base64.3\
 $(builddir)/man/man3/libwget-console.3\
 $(builddir)/man/man3/libwget-dns-caching.3\
 $(builddir)/man/man3/libwget-hash.3\
 $(builddir)/man/man3/libwget-io.3\
 $(builddir)/man/man3/libwget-ip.3\
 $(builddir)/man/man3/libwget-list.3\
 $(builddir)/man/man3/libwget-mem.3\
 $(builddir)/man/man3/libwget-net.3\
 $(builddir)/man/man3/libwget-parse_atom.3\
 $(builddir)/man/man3/libwget-parse_sitemap.3\
 $(builddir)/man/man3/libwget-printf.3\
 $(builddir)/man/man3/libwget-random.3\
 $(builddir)/man/man3/libwget-robots.3\
 $(builddir)/man/man3/libwget-thread.3\
 $(builddir)/man/man3/libwget-utils.3\
 $(builddir)/man/man3/libwget-xalloc.3\
 $(builddir)/man/man3/libwget-xml.3

$(man3_MANS): libwget.stamp

libwget.stamp:
	$(DOXYGEN) $(builddir)/libwget.doxy
	echo > libwget.stamp

man1_MANS = $(builddir)/man/man3/wget2.1

$(man1_MANS): wget2.stamp

wget2.stamp:
	mkdir -p $(builddir)/man/man1
	sh $(srcdir)/wget2_md2man.sh $(srcdir)/wget2.md $(builddir)/man/man1/wget2.1
	pandoc -s -f markdown -t texinfo -o wget2.texi wget2.md
	makeinfo --force wget2.texi
	echo > wget2.stamp

CLEANFILES = libwget.stamp wget2.stamp

all-local: libwget.stamp wget2.stamp

clean-local:
	rm -rf html man

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

$(man3_MANS): doxy.stamp

doxy.stamp:
	$(DOXYGEN) $(builddir)/libwget.doxy
	echo > doxy.stamp

man1_MANS = $(builddir)/man/man3/wget2.1

$(man1_MANS): wget2_md2man.stamp

wget2_md2man.stamp:
	mkdir -p $(builddir)/man/man1
	sh $(srcdir)/wget2_md2man.sh $(srcdir)/wget2_manual.md $(builddir)/man/man1/wget2.1
	echo > wget2_md2man.stamp

CLEANFILES = doxy.stamp wget2_md2man.stamp

all-local: doxy.stamp wget2_md2man.stamp

clean-local:
	rm -rf html man

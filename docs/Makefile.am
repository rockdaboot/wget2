EXTRA_DIST = DoxygenLayout.xml

man3_MANS =\
 $(builddir)/man/man3/libwget-base64.3\
 $(builddir)/man/man3/libwget-console.3\
 $(builddir)/man/man3/libwget-hash.3\
 $(builddir)/man/man3/libwget-io.3\
 $(builddir)/man/man3/libwget-ip.3\
 $(builddir)/man/man3/libwget-list.3\
 $(builddir)/man/man3/libwget-md5.3\
 $(builddir)/man/man3/libwget-mem.3\
 $(builddir)/man/man3/libwget-parse_atom.3\
 $(builddir)/man/man3/libwget-parse_sitemap.3\
 $(builddir)/man/man3/libwget-printf.3\
 $(builddir)/man/man3/libwget-random.3\
 $(builddir)/man/man3/libwget-robots.3\
 $(builddir)/man/man3/libwget-utils.3\
 $(builddir)/man/man3/libwget-xalloc.3\
 $(builddir)/man/man3/libwget-xml.3

$(man3_MANS): doxy.stamp

doxy.stamp:
	$(DOXYGEN) $(builddir)/libwget.doxy
	echo > doxy.stamp

CLEANFILES = doxy.stamp

all-local: doxy.stamp

clean-local:
	rm -rf html man

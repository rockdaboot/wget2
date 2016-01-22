EXTRA_DIST = DoxygenLayout.xml

man3_MANS =\
 $(builddir)/man/man3/libwget-list.3\
 $(builddir)/man/man3/libwget-hash.3\
 $(builddir)/man/man3/libwget-io.3\
 $(builddir)/man/man3/libwget-utils.3\
 $(builddir)/man/man3/libwget-random.3

$(builddir)/man/man3/libwget-list.3: doxy.stamp
$(builddir)/man/man3/libwget-hash.3: doxy.stamp
$(builddir)/man/man3/libwget-io.3: doxy.stamp
$(builddir)/man/man3/libwget-utils.3: doxy.stamp
$(builddir)/man/man3/libwget-random.3: doxy.stamp

doxy.stamp:
	$(DOXYGEN) $(builddir)/libwget.doxy
	echo > doxy.stamp

CLEANFILES = doxy.stamp

all-local: doxy.stamp

clean-local:
	rm -rf html man

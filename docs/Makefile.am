EXTRA_DIST = wget2.md wget-logo.png DoxygenLayout.xml
DISTCLEANFILES =
LOCAL_DISTCLEAN =
STAMPS =

if WITH_DOXYGEN
man3_MANS =\
 $(builddir)/man/man3/libwget-base64.3\
 $(builddir)/man/man3/libwget-bitmap.3\
 $(builddir)/man/man3/libwget-console.3\
 $(builddir)/man/man3/libwget-dns.3\
 $(builddir)/man/man3/libwget-dns-caching.3\
 $(builddir)/man/man3/libwget-error.3\
 $(builddir)/man/man3/libwget-hash.3\
 $(builddir)/man/man3/libwget-hashmap.3\
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
 $(builddir)/man/man3/libwget-stringmap.3\
 $(builddir)/man/man3/libwget-thread.3\
 $(builddir)/man/man3/libwget-utils.3\
 $(builddir)/man/man3/libwget-vector.3\
 $(builddir)/man/man3/libwget-xalloc.3\
 $(builddir)/man/man3/libwget-xml.3

$(man3_MANS): libwget.stamp

libwget.stamp:
	$(AM_V_at)$(DOXYGEN) $(builddir)/libwget.doxy
	$(AM_V_at)echo > libwget.stamp

EXTRA_DIST += $(man3_MANS)
STAMPS += libwget.stamp
LOCAL_DISTCLEAN += html man
endif

if WITH_PANDOC
man1_MANS = $(builddir)/man/man1/wget2.1

$(man1_MANS): wget2.stamp

wget2.stamp:
	$(AM_V_at)mkdir -p $(builddir)/man/man1
	$(AM_V_at)PANDOC=$(PANDOC) sh $(builddir)/wget2_md2man.sh $(srcdir)/wget2.md $(builddir)/man/man1/wget2.1
	$(AM_V_at)$(PANDOC) -s -f markdown -t texinfo -o $(builddir)/wget2.texi $(srcdir)/wget2.md
	$(AM_V_at)$(MAKEINFO) --force -o $(builddir)/wget2.info $(builddir)/wget2.texi
	$(AM_V_at)echo > wget2.stamp

DISTCLEANFILES += wget2.texi wget2.info
EXTRA_DIST += wget2.info $(man1_MANS)
STAMPS += wget2.stamp
endif

CLEANFILES = $(STAMPS)

DISTCLEANFILES += README.md
README.md: $(top_srcdir)/README.md
	$(AM_V_at)sed -n '/# GNU Wget2/,$$p' $(top_srcdir)/README.md >$@

all-local: README.md $(STAMPS)

distclean-local:
	$(AM_V_at)rm -rf $(LOCAL_DISTCLEAN)

DEFS = @DEFS@ \
 -DSRCDIR=\"$(abs_srcdir)\" -DBUILDDIR=\"$(abs_builddir)\" -DEXEEXT=\"$(EXEEXT)\"

MYLIBS = \
 $(CLOCK_TIME_LIB) \
 $(GETADDRINFO_LIB) \
 $(GETHOSTNAME_LIB) \
 $(GETLOGIN_LIB) \
 $(GETRANDOM_LIB) \
 $(HARD_LOCALE_LIB) \
 $(HOSTENT_LIB) \
 $(INET_NTOP_LIB) \
 $(INET_PTON_LIB) \
 $(LIBMULTITHREAD) \
 $(LIBSOCKET) \
 $(LIBTHREAD) \
 $(LIB_CRYPTO) \
 $(LTLIBC32CONV) \
 $(LTLIBICONV) \
 $(LTLIBINTL) \
 $(LTLIBUNISTRING) \
 $(MBRTOWC_LIB) \
 $(NANOSLEEP_LIB) \
 $(POLL_LIB) \
 $(POSIX_SPAWN_LIB) \
 $(PTHREAD_SIGMASK_LIB) \
 $(SELECT_LIB) \
 $(SERVENT_LIB) \
 $(SETLOCALE_LIB) \
 $(SETLOCALE_NULL_LIB) \
 @INTL_MACOSX_LIBS@ \
 $(LIBS) $(CODE_COVERAGE_LIBS)

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) $(TEST_CFLAGS) $(CODE_COVERAGE_CFLAGS) -DMALLOC_RETURNS_NONNULL
AM_CPPFLAGS = -I$(top_srcdir)/include/wget -I$(srcdir) -I$(top_builddir)/lib -I$(top_srcdir)/lib \
 $(CODE_COVERAGE_CPPFLAGS) \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\" \
 -DMALLOC_RETURNS_NONNULL

LDADD = ../src/utils.o libtest.la $(MYLIBS) $(TEST_LIBS)

# test-iri-disabled removed since Wget2 always uses IRIs
WGET_TESTS = test-wget-1$(EXEEXT) test-c-r$(EXEEXT) test-restrict-ascii$(EXEEXT) test-i-http$(EXEEXT) test-i-https$(EXEEXT)\
 test-np$(EXEEXT) test-spider-r$(EXEEXT) test-meta-robots$(EXEEXT) test-idn-robots$(EXEEXT) test-idn-meta$(EXEEXT)\
 test-idn-cmd$(EXEEXT) test-iri$(EXEEXT) test-iri-percent$(EXEEXT) test-iri-list$(EXEEXT) test-iri-forced-remote$(EXEEXT)\
 test-auth-basic$(EXEEXT) test-parse-rss$(EXEEXT) test-page-requisites$(EXEEXT) test-p-nc$(EXEEXT)\
 test-accept$(EXEEXT) test-k$(EXEEXT) test-follow-tags$(EXEEXT) test-directory-clash$(EXEEXT) test-redirection$(EXEEXT)\
 test-base$(EXEEXT) test-metalink$(EXEEXT) test-robots$(EXEEXT) test-robots-off$(EXEEXT) test-parse-css$(EXEEXT) test-bad-chunk$(EXEEXT)\
 test-iri-subdir$(EXEEXT) test-chunked$(EXEEXT) test-cut-dirs$(EXEEXT) test-cut-get-vars$(EXEEXT) test-parse-html-css$(EXEEXT)\
 test-auth-digest$(EXEEXT) test-stats-dns$(EXEEXT) test-stats-tls$(EXEEXT) test-stats-site$(EXEEXT) test-stats-ocsp$(EXEEXT)\
 test-plugin-interception$(EXEEXT) test-plugin-nonexistance$(EXEEXT) test-plugin-failure$(EXEEXT) test-filter-mime-type$(EXEEXT)\
 test-https-enforce-hard1$(EXEEXT) test-https-enforce-hard2$(EXEEXT) test-https-enforce-hard3$(EXEEXT)\
 test-https-enforce-soft1$(EXEEXT) test-https-enforce-soft2$(EXEEXT) test-https-enforce-soft3$(EXEEXT)\
 test-gzip$(EXEEXT) test-compression$(EXEEXT) test-include-and-exclude-directories$(EXEEXT) test-save-content-on$(EXEEXT)\
 test-limit-rate$(EXEEXT) test-interrupt-response$(EXEEXT) test-post-handshake-auth$(EXEEXT) test-unlink$(EXEEXT)\
 test-ocsp-server$(EXEEXT) test-ocsp-stap$(EXEEXT) test-limit-rate-http2$(EXEEXT) test-timestamping$(EXEEXT)\
 test-cookies$(EXEEXT) test-E-k$(EXEEXT) test-ignore-length$(EXEEXT) test-convert-file-only$(EXEEXT)\
 test-download-attr$(EXEEXT) test-directory-prefix$(EXEEXT) test-level$(EXEEXT)
#test-post-file$(EXEEXT) test-cookies-http_state$(EXEEXT)

if WITH_GPGME
 WGET_TESTS += test-gpg-valid$(EXEEXT) test-gpg-invalid$(EXEEXT) test-gpg-missing$(EXEEXT) test-gpg-styles$(EXEEXT) test-gpg-bad$(EXEEXT) \
 test-gpg-save-failed$(EXEEXT) test-gpg-verify-no-file$(EXEEXT)
 test_gpg_valid_SOURCES = test-gpg-valid.c gpg-test-util.h
 test_gpg_invalid_SOURCES = test-gpg-invalid.c gpg-test-util.h
 test_gpg_missing_SOURCES = test-gpg-missing.c gpg-test-util.h
 test_gpg_bad_SOURCES = test-gpg-bad.c gpg-test-util.h
endif

if PLUGIN_SUPPORT
 WGET_TESTS += test-plugin$(EXEEXT)
 check_LTLIBRARIES = libpluginname.la libpluginexit.la libpluginoption.la libpluginfaulty1.la libpluginfaulty2.la \
  libpluginapi.la libplugindb.la
endif

check_PROGRAMS = $(WGET_TESTS)

test_stats_dns_SOURCES = test-stats-dns.c stats-test-util.h
test_stats_ocsp_SOURCES = test-stats-ocsp.c stats-test-util.h
test_stats_site_SOURCES = test-stats-site.c stats-test-util.h
test_stats_tls_SOURCES = test-stats-tls.c stats-test-util.h

noinst_LTLIBRARIES = libtest.la
libtest_la_SOURCES = libtest.c libtest.h
libtest_la_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include/wget -I$(top_builddir)/lib -I$(top_srcdir)/lib $(CFLAG_VISIBILITY) -DBUILDING_LIBWGET \
 -DWGETVER_FILE=\"$(top_builddir)/include/wget/wgetver.h\"
libtest_la_LIBADD = ../src/libtest-utils.la ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

EXTRA_DIST = certs gpg valgrind-suppressions clang-asan-suppressions

clean-local:
	rm -rf $(srcdir)/.test_*

AM_TESTS_ENVIRONMENT = export VALGRIND_TESTS"=@VALGRIND_TESTS@";\
 export LSAN_OPTIONS=suppressions="$(abs_srcdir)/clang-asan-suppressions";
TESTS = $(WGET_TESTS)

#Test plugins for plugin related testing
dummy_ldflags = -avoid-version -module -shared -no-undefined \
	-rpath $(abs_builddir)

libpluginname_la_SOURCES = test-plugin-dummy.c plugin_tests.h
libpluginname_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_NAME
libpluginname_la_LDFLAGS = $(dummy_ldflags)
libpluginname_la_LIBADD = ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

libpluginexit_la_SOURCES = test-plugin-dummy.c plugin_tests.h
libpluginexit_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_EXITSTATUS
libpluginexit_la_LDFLAGS = $(dummy_ldflags)
libpluginexit_la_LIBADD = ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

libpluginfaulty1_la_SOURCES = test-plugin-dummy.c plugin_tests.h
libpluginfaulty1_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_FAULTY1
libpluginfaulty1_la_LDFLAGS = $(dummy_ldflags)
libpluginfaulty1_la_LIBADD =  ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

libpluginfaulty2_la_SOURCES = test-plugin-dummy.c plugin_tests.h
libpluginfaulty2_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_FAULTY2
libpluginfaulty2_la_LDFLAGS = $(dummy_ldflags)
libpluginfaulty2_la_LIBADD = ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

libpluginoption_la_SOURCES = test-plugin-dummy.c plugin_tests.h
libpluginoption_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_OPTIONS
libpluginoption_la_LDFLAGS = $(dummy_ldflags)
libpluginoption_la_LIBADD = ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

libpluginapi_la_SOURCES = test-plugin-dummy.c plugin_tests.h
libpluginapi_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_API
libpluginapi_la_LDFLAGS = $(dummy_ldflags)
libpluginapi_la_LIBADD = ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

libplugindb_la_SOURCES = test-plugin-dummy.c plugin_tests.h
libplugindb_la_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_SELECT_DATABASE
libplugindb_la_LDFLAGS = $(dummy_ldflags)
libplugindb_la_LIBADD = ../lib/libgnu.la ../libwget/libwget.la $(MYLIBS)

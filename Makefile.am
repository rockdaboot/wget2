# got some hints from https://gitorious.org/openismus-playground/examplelib/source

if HAVE_PO
SUBDIRS = po
else
SUBDIRS =
endif

SUBDIRS += lib include libwget examples src data $(LIBWGET_DOCS) tests

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information. Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libwget.pc

EXTRA_DIST = build-aux/config.rpath m4/gnulib-cache.m4

dist-hook: gen-ChangeLog

.PHONY: gen-ChangeLog check-valgrind

gen-ChangeLog:
	$(AM_V_GEN)if test -d .git; then              \
	  log_fix="$(srcdir)/build-aux/git-log-fix";  \
	  test -e "$$log_fix" || amend_git_log=;      \
	  $(top_srcdir)/build-aux/gitlog-to-changelog \
	    $$amend_git_log > $(distdir)/ChangeLog;   \
	fi

check-valgrind:
	TESTS_ENVIRONMENT="VALGRIND_TESTS=1" $(MAKE) check

clean-lcov:
	rm -rf wget2_base.info wget2_test.info wget2_total.info */*.gc?? lcov/
	lcov --zerocounters --directory src/ --directory libwget/

check-coverage: clean clean-lcov
	$(MAKE) CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	lcov --capture --no-external --initial --directory src/ --directory libwget/ --output-file wget2_base.info
	$(MAKE) CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage" VALGRIND_TESTS=0 check
	lcov --capture --no-external --ignore-errors source --directory src/ --directory libwget/ --output-file wget2_test.info
	lcov -a wget2_base.info -a wget2_test.info -o wget2_total.info
	lcov --remove wget2_total.info 'libwget/test_linking.c' 'libwget/css_tokenizer.lex' 'libwget/<stdout>' -o wget2_total.info
	genhtml --prefix . --ignore-errors source wget2_total.info --legend --title "Wget2" --output-directory=lcov

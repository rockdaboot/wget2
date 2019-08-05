# got some hints from https://gitorious.org/openismus-playground/examplelib/source

SUBDIRS = lib include libwget examples src

if HAVE_PO
SUBDIRS += po
endif

if WITH_DOCS
SUBDIRS += docs
endif

SUBDIRS += fuzz unit-tests

if WITH_MICROHTTPD
SUBDIRS += tests
endif

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information. Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libwget.pc

EXTRA_DIST = cfg.mk build-aux/config.rpath m4/gnulib-cache.m4 README.md contrib/check_options

include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean

dist-hook: gen-ChangeLog

.PHONY: gen-ChangeLog check-valgrind

gen-ChangeLog:
	$(AM_V_GEN)if test -d .git; then \
	  git log --no-merges --date=short \
	    --pretty='format:%ad %an <%ae>%w(0,0,5)%+B' | sed '/^[1-9].*/G' \
	    > $(distdir)/ChangeLog; \
	fi

check-valgrind:
	TESTS_ENVIRONMENT="VALGRIND_TESTS=1" $(MAKE) check

clean-lcov:
	rm -rf wget2.info */*.gc?? */.libs/*.gc?? lcov/
	lcov --zerocounters --directory src/ --directory libwget/

LCOV_INFO=wget2.info
check-coverage: clean clean-lcov
	$(MAKE) CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	lcov --capture --initial --directory src/ --directory libwget/.libs --output-file $(LCOV_INFO)
	$(MAKE) CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage" VALGRIND_TESTS=0 check
	lcov --capture --directory src/ --directory libwget/.libs --output-file $(LCOV_INFO)
	lcov --remove $(LCOV_INFO) '*/test_linking.c' '*/css_tokenizer.lex' -o $(LCOV_INFO)
	genhtml --prefix . --ignore-errors source $(LCOV_INFO) --legend --title "Wget2" --output-directory=lcov
	@echo
	@echo "You can now view the coverage report with 'xdg-open lcov/index.html'"

fuzz-coverage: clean clean-lcov
	$(MAKE) -C lib
	$(MAKE) -C libwget CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	$(MAKE) -C src CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	$(MAKE) -C fuzz check CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	lcov --capture --initial --directory libwget/.libs --directory fuzz --directory src --output-file $(LCOV_INFO)
	lcov --capture --directory libwget/.libs --directory fuzz --directory src --output-file $(LCOV_INFO)
	lcov --remove $(LCOV_INFO) '*/test_linking.c' '*/css_tokenizer.lex' -o $(LCOV_INFO)
	genhtml --prefix . --ignore-errors source $(LCOV_INFO) --legend --title "Wget2-fuzz" --output-directory=lcov
	@echo
	@echo "You can now view the coverage report with 'xdg-open lcov/index.html'"

check-local:
	$(AM_V_at)$(MAKE) -s syntax-check >/dev/null
	$(AM_V_at)$(srcdir)/contrib/check_options $(srcdir)/docs/wget2.md $(builddir)/src/wget2$(EXEEXT)

# ppl often forget to run ldconfig after an install, so let's do it here
install-exec-hook:
	$(AM_V_at)$(LDCONFIG) || :

# Copyright (C) 2015-2024 Free Software Foundation, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Makefile template for automake
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
if WITH_GNUTLS
SUBDIRS += tests
endif
endif

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

## Install the generated pkg-config file (.pc) into the expected location for
## architecture-dependent package configuration information. Occasionally,
## pkg-config files are also used for architecture-independent data packages,
## in which case the correct install location would be $(datadir)/pkgconfig.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libwget.pc

EXTRA_DIST = cfg.mk build-aux/config.rpath m4/gnulib-cache.m4 README.md \
             contrib/check_options

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
	lcov --capture --initial --ignore-errors range --directory src/ --directory libwget/.libs --output-file $(LCOV_INFO)
	$(MAKE) CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage" VALGRIND_TESTS=0 check
	lcov --capture --ignore-errors range --directory src/ --directory libwget/.libs --output-file $(LCOV_INFO)
	lcov --ignore-errors range --remove $(LCOV_INFO) '*/css_tokenizer.lex' -o $(LCOV_INFO)
	genhtml --prefix . --ignore-errors source,range $(LCOV_INFO) --legend --title "Wget2" --output-directory=lcov
	@echo
	@echo "You can now view the coverage report with 'xdg-open lcov/index.html'"

fuzz-coverage: clean clean-lcov
	$(MAKE) -C lib
	$(MAKE) -C libwget CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	$(MAKE) -C src CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	$(MAKE) -C fuzz check CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	lcov --capture --initial --ignore-errors range --directory fuzz --directory src --directory libwget/.libs --output-file $(LCOV_INFO)
	lcov --capture --ignore-errors range --directory libwget/.libs --directory fuzz --directory src --output-file $(LCOV_INFO)
	lcov --remove $(LCOV_INFO) '*/css_tokenizer.lex' -o $(LCOV_INFO)
	genhtml --prefix . --ignore-errors source,range $(LCOV_INFO) --legend --title "Wget2-fuzz" --output-directory=lcov
	@echo
	@echo "You can now view the coverage report with 'xdg-open lcov/index.html'"

check-local:
	$(AM_V_at)$(srcdir)/contrib/check_options $(srcdir)/docs/wget2.md $(builddir)/src/wget2$(EXEEXT)

# ppl often forget to run ldconfig after an install, so let's do it here
install-exec-hook:
	$(AM_V_at)$(LDCONFIG) || :

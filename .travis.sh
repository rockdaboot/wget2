#!/bin/bash

set -e

BOOTSTRAP_OPTIONS=
CONFIGURE_OPTIONS=()
export CFLAGS="-O0 -g"

test "$CC" = "clang" && export CXX="clang++"

if [[ $TRAVIS_OS_NAME = 'osx' ]]; then
	CONFIGURE_OPTIONS+=("")
	# Install Libmicrohttpd from source
	cd ..
	wget http://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-0.9.55.tar.gz
	tar zxf libmicrohttpd-0.9.55.tar.gz && cd libmicrohttpd-0.9.55
	./configure
	make clean
	make -j3
	make install
	cd - && cd wget2
else
	CONFIGURE_OPTIONS+=("--enable-valgrind-tests")
fi

./bootstrap ${BOOTSTRAP_OPTIONS}

for OPTS in "${CONFIGURE_OPTIONS[@]}"; do
	./configure -C $OPTS
	if test "$TRAVIS_OS_NAME" = 'osx'; then
		# On OSX we are unable to find the Wget2 dylibs without
		# installing first. However `make install` on linux systems
		# fail due to insufficient permissions
		make install -j3
	fi
	if make clean check -j3; then :; else
		test -f fuzz/test-suite.log && cat fuzz/test-suite.log
		test -f unit-tests/test-suite.log && cat unit-tests/test-suite.log
		test -f tests/test-suite.log && cat tests/test-suite.log
		exit 1
	fi
done

make distcheck -j3

if [[ $CC = 'gcc' && $TRAVIS_OS_NAME = 'linux' ]]; then
	make check-coverage
	coveralls --include libwget/ --include src/ -e "libwget/<stdout>" -e lib/ -e tests/
fi

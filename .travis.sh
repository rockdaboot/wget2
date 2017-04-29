#!/bin/bash

set -e

BOOTSTRAP_OPTIONS=
CONFIGURE_OPTIONS=()
export CFLAGS="-O0 -g"

if [[ $TRAVIS_OS_NAME = 'osx' ]]; then
	CONFIGURE_OPTIONS+=("")
else
	CONFIGURE_OPTIONS+=("--enable-fsanitize-asan --enable-fsanitize-ubsan")
	CONFIGURE_OPTIONS+=("--enable-valgrind-tests")
fi

./bootstrap ${BOOTSTRAP_OPTIONS}

# On OSX we are unable to find the Wget2 dylibs without installing first
# However `make install` on linux systems fail due to insufficient permissions
if [[ $TRAVIS_OS_NAME = 'osx' ]]; then
	./configure -C
	make install -j3
fi

for OPTS in "${CONFIGURE_OPTIONS[@]}"; do
	./configure -C $OPTS
	make clean check -j3 || (cat tests/test-suite.log && exit 1)
done

make distcheck -j3

if [[ $CC = 'gcc' && $TRAVIS_OS_NAME = 'linux' ]]; then
	make check-coverage
	coveralls --include libwget/ --include src/ -e "libwget/<stdout>" -e lib/ -e tests/
fi

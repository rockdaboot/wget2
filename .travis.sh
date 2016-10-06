#!/bin/bash

./bootstrap || exit 1
if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
	./configure || exit 1
else
	./configure --enable-fsanitize-ubsan --enable-fsanitize-asan || exit 1
fi
make -j3 || exit 1
if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
  make install || exit 1
else
  export VALGRIND_TESTS=1
fi
make check -j3
#if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
# cat tests/test.log
# ls -la tests/.test_*
# for log in tests/*.log; do
#   echo -e "\n#### $log ####"
#   cat $log
# done
#fi
make distcheck
if [[ $CC == "gcc" && $TRAVIS_OS_NAME == 'linux' ]]; then
  make check-coverage
  coveralls --include libwget/ --include src/ -e "libwget/<stdout>" -e lib/ -e tests/
fi

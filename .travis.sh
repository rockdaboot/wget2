#!/bin/bash

./autogen.sh || exit 1
./configure --enable-gcc-warnings || exit 1
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

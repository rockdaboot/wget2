#!/bin/bash

./autogen.sh || exit 1
./configure || exit 1
make -j3 || exit 1
if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
  make install || exit 1
fi
make check -j3
#if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
# ls -la tests/.test_*
# for log in tests/*.log; do
#   echo -e "\n#### $log ####"
#   cat $log
# done
#fi
make distcheck

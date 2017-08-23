#!/bin/bash -eu
#
# (C)2017 Tim Ruehsen tim.ruehsen@gmx.de
#
# View the coverage report for one or more fuzzers.

# 1. execute 'make fuzz-coverage' in the top directory
# 2. execute './view-coverage.sh <fuzz target(s)>

# Example with single fuzzer:
#   ./view-coverage.sh libwget_xml_parse_buffer_fuzzer

# Example with two fuzzers:
#   ./view-coverage.sh libwget_xml_parse_buffer_fuzzer libwget_metalink_parse_fuzzer

if test -z "$1"; then
  echo "Usage: $0 <fuzz target(s)>"
  echo "Example: $0 libwget_xml_parse_buffer_fuzzer"
  exit 1
fi

#fuzzer="./"$1
LCOV_INFO=coverage.info
#./coverage.sh $fuzzer
#lcov --capture --initial --directory ../libwget/.libs --directory . --output-file $LCOV_INFO
#lcov --capture --directory ../libwget/.libs --output-file $LCOV_INFO
#lcov --remove $LCOV_INFO '*/test_linking.c' '*/css_tokenizer.lex' '*/<stdout>' '*/*.h' -o $LCOV_INFO
#genhtml --prefix . --ignore-errors source $LCOV_INFO --legend --title "$1" --output-directory=lcov

lcov --zerocounters --directory ../libwget/
lcov --capture --initial --directory ../libwget/.libs --directory . --output-file $LCOV_INFO
make check TESTS="$*" CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
lcov --capture --directory ../libwget/.libs --output-file $LCOV_INFO
lcov --remove $LCOV_INFO '*/test_linking.c' '*/css_tokenizer.lex' '*/*.h' -o $LCOV_INFO
genhtml --prefix . --ignore-errors source $LCOV_INFO --legend --title "$*" --output-directory=lcov

xdg-open lcov/index.html

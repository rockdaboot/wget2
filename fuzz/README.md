# Fuzzers

These are fuzzers designed for use with `libFuzzer` or `afl`. They can
be used to run on Google's OSS-Fuzz (https://github.com/google/oss-fuzz/).

The convention used here is that the initial values for each parser fuzzer
are taken from the $NAME.in directory.

Crash reproducers from OSS-Fuzz are put into $NAME.repro directory for
regression testing with top dir 'make check' or 'make check-valgrind'.

# Running a fuzzer using clang

Use the following commands on top dir:
```
export CC=clang-5.0
export CXX=clang++-5.0
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize-coverage=trace-pc-guard,trace-cmp"
export CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize-coverage=trace-pc-guard,trace-cmp -stdlib=libc++"
./configure --enable-static --disable-doc --disable-manywarnings
make clean
make -j$(nproc)
cd fuzz

./run-clang.sh libwget_xml_parse_buffer_fuzzer
```

# Running a fuzzer using AFL

Use the following commands on top dir:

```
$ CC=afl-clang-fast ./configure --disable-doc
$ make -j$(nproc) clean all
$ cd fuzz
$ ./run-afl.sh libwget_xml_parse_buffer_fuzzer
```

# Enhancing the testsuite for issues found

For the following tests dropping a file to a subdirectory in tests is
sufficient:

|--------------------------------|--------------------------------|
|libwget_xml_parse_buffer        | tests/libwget_xml_parse_buffer |
|--------------------------------|--------------------------------|

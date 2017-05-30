# Fuzzers

These are fuzzers designed for use with `libFuzzer` or `afl`. They can
be used to run on Google's OSS-Fuzz (https://github.com/google/oss-fuzz/).

The convention used here is that the initial values for each parser fuzzer
are taken from the $NAME.in directory.

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

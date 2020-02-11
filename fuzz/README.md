# Fuzzers

These are fuzzers designed for use with `libFuzzer` or `afl`. They can
be used to run on Google's OSS-Fuzz (https://github.com/google/oss-fuzz/).

The convention used here is that the initial values for each parser fuzzer
are taken from the $NAME.in directory ($NAME is the name of the fuzzer, e.g.
'libwget_xml_parse_buffer_fuzzer').

Crash reproducers from OSS-Fuzz are put into $NAME.repro directory for
regression testing with top dir 'make check' or 'make check-valgrind'.

The script `get_ossfuzz_corpora` downloads the corpora from OSS-Fuzz for
the given fuzzer. It puts those files together with the local ones and performs
a 'merge' step to remove superfluous corpora. The next step would be to add
changed/new corpora to the git repository.

Example:
```
./get_ossfuzz_corpora libwget_xml_parse_buffer_fuzzer
git add libwget_xml_parse_buffer_fuzzer.in/*
git commit -a -m "Update OSS-Fuzz corpora"
(create a branch and push if something changed)
(create a MR)
```

Since there are quite a few fuzzers now, you can update all their corpora
in one step with `./get_all_corpora`. Do this from time to time to stay
in sync with OSS-Fuzz. Whenever library code or fuzzers change, there might
me new corpora after 1-2 days.


# Running a fuzzer using clang and libFuzzer

Use the following commands on top dir:
```
export CC=clang
#export CFLAGS="-O1 -g -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=undefined,integer,nullability,bool,alignment,null,enum,address,leak,nonnull-attribute -fsanitize=address -fsanitize-address-use-after-scope -fsanitize-coverage=trace-pc-guard,trace-cmp"

export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=bool,array-bounds,float-divide-by-zero,function,integer-divide-by-zero,return,shift,signed-integer-overflow,vla-bound,vptr -fno-sanitize-recover=bool,array-bounds,float-divide-by-zero,function,integer-divide-by-zero,return,shift,signed-integer-overflow,vla-bound,vptr -fsanitize=fuzzer-no-link"

export LIB_FUZZING_ENGINE="-lFuzzer -lstdc++"
./configure --enable-fuzzing --disable-doc --disable-manywarnings
make clean
make -j$(nproc)
cd fuzz

# run libwget_xml_parse_buffer_fuzzer
export UBSAN_OPTIONS=print_stacktrace=1:report_error_type=1
export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
./run-clang.sh libwget_xml_parse_buffer_fuzzer
```

If you see a crash, then a crash corpora is written that can be used for further
investigation. E.g.
```
==2410==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000004e90 at pc 0x00000049cf9c bp 0x7fffb5543f70 sp 0x7fffb5543720
...
Test unit written to ./crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
```

To reproduce the crash:
```
./libwget_xml_parse_buffer_fuzzer < ./crash-adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
```

You can also copy/move that file into libwget_xml_parse_buffer_fuzzer.repro/
and re-build the project without fuzzing for a valgrind run, if you like that better.
Just a `./configure` (maybe with sanitizers enabled) and a `make check-valgrind` should reproduce it.


# Running a fuzzer using AFL

Use the following commands on top dir:

```
$ CC=afl-clang-fast ./configure --disable-doc
$ make -j$(nproc) clean all
$ cd fuzz
$ ./run-afl.sh libwget_xml_parse_buffer_fuzzer
```

# Fuzz code coverage using the corpus directories *.in/

Code coverage reports currently work best with gcc+lcov+genhtml.

In the top directory:
```
CC=gcc CFLAGS="-O0 -g" ./configure --disable-doc --disable-manywarnings
make fuzz-coverage
xdg-open lcov/index.html
```

Each fuzzer target has it's own files/functions to cover, e.g.
`libwget_xml_parse_buffer` covers libwget/xml.c (except
 wget_xml_parse_file() and wget_html_parse_file()).

To work on corpora for better coverage, `cd fuzz` and use e.g.
`./view-coverage.sh libwget_xml_parse_buffer_fuzzer`.


# Creating wget_options_fuzzer.dict

```
for i in `../src/wget2 --help|tr ' ' '\n'|grep ^--|cut -c 3-|sort`;do echo \"$i\"; done >wget_options_fuzzer.dict
```

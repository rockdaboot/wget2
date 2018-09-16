We have three test directories used by `make check`.

**fuzz/**

This directory contains C files that either work as tests for `make check` or as fuzzers for local fuzzing and continuous fuzzing by Google's OSS-Fuzz.

`make check` builds the executables in a way that all input files (so-called corpora) in the appropriate .in/ directories are worked on. These files are the output from fuzzing and (should) cover most of the code paths for the functions to be tested. Whenever changes in the our code introduce memory issues or undefined behavior, these tests should fail. Of course this is only true for the code that is tested... we are far from 100% coverage.

If you are interested in fuzzing or in writing more fuzzers, check out `fuzz/README.md`.

Normally, you won't bother with these files.

**unit-tests/**

Here we test library functions. You can either add your tests in `test.c` or for very special tests you create an own .c file and add it to `Makefile.am`.

**tests/**

Here we test the `wget2` utility. Each `test*.c` file has one or more tests inside.
Put related tests into one C file. 'Related' could be one option with different input files or in combination with other options.

For a new C test file copy a fitting existing one. It should be pretty self-explanatory and straight forward.

If you want to run just the tests contained at this directory please type: `make check -C tests`

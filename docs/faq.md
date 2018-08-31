# Wget2 FAQ (Frequently Asked Questions)

* [User Questions](#User Questions)
  * [What means "Failed to connect: Wget has been built without TLS support" ?](#missing-gnutls)
* [Developer Questions](#Developer Questions)
  * [How to do valgrind testing ?](#valgrind)
  * [How to get a test coverage report ?](#coverage)
  * [How to enable Control Flow Integrity (CFI) with clang ?](#cfi)
  * [How to add a new command line option ?](#addOption)

# <a name="User Questions"/>User Questions

Questions regarding wget2 usage


## <a name="missing-gnutls"/> What means "Failed to connect: Wget has been built without TLS support" ?

Wget2 has been built without TLS support. You should install the gnutls development files and build again.

On Debian / Ubuntu you install those files with `apt-get install gnutls-dev`.

The `./configure` run outputs a summary at the end. If GnuTLS has been detected, you'll see
```
SSL/TLS support:    yes
```


# <a name="Developer Questions"/>Developer Questions

Questions regarding building wget2, about the codebase, how to add features, ...

Please first read the short [Introduction](index.html) where you find basic information.


## <a name="valgrind"/>How to do valgrind testing ?

To run the complete test suite with valgrind memcheck

		make check-valgrind

or if you want valgrind memcheck by default

		./configure --enable-valgrind-tests
		make check

To run single tests with valgrind (e.g. for `test-k`)

		cd tests
		VALGRIND_TESTS=1 ./test-k

Why not directly using valgrind like `valgrind --leak-check=full ./test-k` ?
Well, you want to valgrind 'wget2' and not the test program itself, right ?

Another way to run single tests with valgrind (e.g. for `test-k`) from the main directory

		TESTS_ENVIRONMENT="VALGRIND_TESTS=1" make check -C tests TESTS="test-k"


## <a name="coverage"/>How to get a test coverage report ?

To generate and view the test code coverage (works with gcc, not with clang)

		make check-coverage
		xdg-open lcov/index.html


## <a name="cfi"/>How to enable Control Flow Integrity (CFI) with clang ?

To instrument clang's [CFI](https://clang.llvm.org/docs/ControlFlowIntegrity.html):

		CC="clang-5.0" CFLAGS="-g -fsanitize=cfi -fno-sanitize-trap=all -fno-sanitize=cfi-icall -flto -fvisibility=hidden" NM=/usr/bin/llvm-nm-5.0 RANLIB=/usr/bin/llvm-ranlib-5.0 AR=/usr/bin/llvm-ar-5.0 LD=/usr/bin/gold ./configure
		make clean
		make check

With clang-5.0 `-fsanitize=cfi-icall` does not work as expected.
Our logger callback functions are typed correctly, but falsely cause a hiccup.

## <a name="addOption"/>How to add a new command line option ?

Wget2 support many command line options, which are listed [here](wget2.md#Options). To add
a new one:

 - Extend wget_options.h/struct config with the needed variable
 - Add a default value for your variable in the 'config' initializer if needed (in options.c)
 - Add the long option into 'options[]' (in options.c). keep alphabetical order !
 - If appropriate, add a new parse function (see examples in options.c)
 - Extend the documentation (at docs/wget2.md)
 - Set args to -1 if value for an option is optional

You can find more information about the option handling in Wget2 at [our wiki](https://gitlab.com/gnuwget/wget2/wikis/Documentation/OptionHandling)

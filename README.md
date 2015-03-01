[![Build Status](https://travis-ci.org/rockdaboot/mget.png?branch=develop)](https://travis-ci.org/rockdaboot/mget)
[![Coverity Scan Status](https://scan.coverity.com/projects/4414/badge.svg)](https://scan.coverity.com/projects/4414)

Mget - multithreaded metalink / file / website downloader / spider and library
==============================================================================

This is a multithreaded Wget-like tool and library written in C.

Designed and written from scratch it requires a C99 and Posix compliant
development environment.

Included is the stand-alone library libmget which provides an interface
to many useful functions used by Mget.

The originally purpose was to help out on Wget2 development (refactoring,
modern and clean code, new technology, new design).

In many cases Mget downloads much faster than Wget1.14 due to HTTP zlib
compression, parallel connections and use of If-Modified-Since HTTP header.

It consumes less system and user CPU cycles due to larger buffers and
buffer recycling.

License
-------

Mget is licensed under GPLv3+.<br>
Libmget is licensed under LGPLv3+.

Contact
-------

[Project](https://github.com/rockdaboot/mget)<br>
[Website](http://rockdaboot.github.io/mget)<br>
[Mailing List](https://groups.google.com/forum/#!forum/mget-bugs)

To join the mailing list send an email to

<mget-bugs+subscribe@googlegroups.com>

and follow the instructions provided by the answer mail.

Or click [join](https://groups.google.com/forum/#!forum/mget-bugs/join).

Development Status
------------------

Mget has already many features that go beyond what Wget provides.<br>

An incomplete list of implemented features:

- OCSP stapling + OCSP server querying as a fallback (experimental, needs GnuTLS >= 3.3.11)
- Use [libpsl](https://github.com/rockdaboot/libpsl) for cookie domain checking (using Public Suffix List)
- Support link conversion (-k/--convert-links and -K/--backup-converted)
- Support for RFC 6266 compliant Content-Disposition
- RFC 6797 HSTS (HTTP Strict Transport Security)
- Support for bzip2 Content-Encoding / Accept-Encoding compression type
- New Year gimmick: added support for XZ Content-Encoding / Accept-Encoding compression type
- Character encoding of input files may be specified despite from local and remote encoding (--input-encoding)
- Support scanning RSS 2.0 feeds from local files (--force-rss -i <filename>)
- Support scanning RSS 2.0 feeds.
- Support scanning Atom 1.0 feeds from local files (--force-atom -i <filename>)
- Support scanning Atom 1.0 feeds.
- Support scanning URLs from local Sitemap XML file (--force-sitemap -i <filename>)
- Support scanning sitemap files given in robots.txt (Sitemap XML, gzipped Sitemap XML, plain text) including
sitemap index files.
- Support arbitrary number of proxies for parallel downloads
- Multithreaded download of single files (option --chunk-size)
- Internationalized Domain Names in Applications (compile-selectable IDNA2008 or IDNA2003)
- ICEcast / SHOUTcast support via library (see examples/getstream.c)
- respect /robots.txt "Robot Exclusion Standard" and `<META name="robots" ...>`
- new option --secure-protocol=PFS to have TLS only plus forcing Perfect Forward Secrecy (PFS)
- use TCP Fast Open if available
- IDN support for international domains
- autotools support
- proxy support
- cookies (session/non-session), detection of supercookies via Mozilla Public Suffix List
  (use the new option --cookie-suffixes <filename>, better: put it into ~/.mgetrc)
- recursive download of websites with or without spanning hosts
- download of single web pages / resources
- zlib/gzip compressed HTTP/HTTPS downloads (gzip, deflate)
- number of parallel download threads is adjustable
- include directive for config files (wildcards allowed)
- support for keep-alive connections
- included CSS, HTML, XML parser needed for recursive downloads
- gettext support
- HTTPS via libgnutls
- support for Metalink RFC 6249 (Metalink/HTTP: Mirrors and Hashes)
- support for Metalink RFC 5854 (Metalink Download Description Format / .meta4 files)
- support for Metalink 3
- Metalink checksumming via libgnutls
- DNS lookup cache
- IPv4 and IPv6 support
- tested on Debian SID amd64 and OpenBSD 5.0
- compiled and tested with gcc (4.7.1 upto 4.8.2) and clang (3.1.1 upto 3.4)
- tested regularly with static analysis tools
- compiled and linked with hardening options proposed by the Debian project

Anybody should feel free to contribute ideas, opinions, knowledge, code, tests, etc.

Not yet implemented
-------------------

The following is just a quick list of ideas and todos.<br>
The mid-range goal is to come as close to Wget, that Wget's units test work for Mget.

Some ideas of what could be done next (but contact me before you start bigger changes!):

- [EFF HTTPS Everywhere](https://www.eff.org/https-everywhere)
- SSH-style TOFU (Trust On First Use)
- DANE / DNSSEC (waiting for Debian to have libdane from GnuTLS... but that needs libunbound work with GnuTLS, right
  now it only works with OpenSSL.)
- WARC support
- read credentials from secure wallets (e.g. kwallet, firefox, http://sourceforge.net/projects/passwordsafe/)
  [Chromium HSTS domain list](http://src.chromium.org/viewvc/chrome/trunk/src/net/http/transport_security_state_static.json)
- HTTP request pipelining
- SPDY / HTTP2.0 protocol
- respect data-urls
- Streaming (.m3u, etc. formats)
- ftp support
- https with openssl
- a progress display
- Documentation docbook with free Serna WYSIWYG/WYMIWYG editor (conversion to texinfo possible)
  and/or with doxygen (API docs embedded into source code)
- plugin technology to plug in user-specific code


Requirements
------------

The following packages are needed to build Mget:

* autotools (autoconf, autogen, automake, autopoint, libtool)
* pkg-config >= 0.28 (recommended)
* gtk-doc-tools (when creating the HTML documentation)
* xsltproc (when creating man pages)
* gettext >= 0.18.1
* libz >= 1.2.3 (the distribution may call the package zlib*, eg. zlib1g on Debian)
* liblzma >= 5.1.1alpha (optional, if you want HTTP lzma decompression)
* libbz2 >= 1.0.6 (optional, if you want HTTP bzip2 decompression)
* libgnutls >= 2.10.0
* libidn2 >= 0.9 + libunistring >= 0.9.3 (libidn >= 1.25 if you don't have libidn2)
* flex >= 2.5.35
* libpsl >= 0.5.0

The versions are recommended, but older versions may also work.


Building from git
-----------------

Download project and prepare sources with

		git clone http://github.com/rockdaboot/mget
		./autogen.sh

Build Mget with

		./configure
		make

Test the functionality

		make check

Install Mget and libmget

		sudo make install (or su -c "make install")

To create Mget HTML documentation

		./configure --enable-gtk-doc
		make

To create Mget HTML documentation and man pages

		./configure --enable-gtk-doc --enable-man
		make

Valgrind Testing
----------------

To run the test suite with valgrind memcheck

		TESTS_ENVIRONMENT="VALGRIND_TESTS=1" make check

or if you want valgrind memcheck by default

		./configure --enable-valgrind-tests
		make check

To run single tests with valgrind (e.g. test-k)

		cd tests
		VALGRIND_TESTS=1 ./test-k

Why not directly using valgrind like 'valgrind --leak-check=full ./test-k' ?
Well, you want to valgrind 'mget' and not the test program itself, right ?

Documentation
-------------

There is no own documentation yet, but Mget aims to be Wget1.14 compatible.

		mget --help

prints the usage and the current set of integrated options.
For more info, see the man pages of Wget.

The Mget library API documentation has been started.

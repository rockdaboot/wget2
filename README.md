[![Build Status](https://travis-ci.org/rockdaboot/wget2.svg?branch=wget2)](https://travis-ci.org/rockdaboot/wget2)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7852/badge.svg)](https://scan.coverity.com/projects/rockdaboot-wget2)
[![Coverage Status](https://coveralls.io/repos/github/rockdaboot/wget2/badge.svg?branch=master)](https://coveralls.io/github/rockdaboot/wget2?branch=master)

Solaris OpenCSW [![Build Status Solaris amd64](https://buildfarm.opencsw.org/buildbot/png?builder=wget2-solaris10-amd64)](https://buildfarm.opencsw.org/buildbot/builders/wget2-solaris10-amd64)
[![Build Status Solaris i386](https://buildfarm.opencsw.org/buildbot/png?builder=wget2-solaris10-i386)](https://buildfarm.opencsw.org/buildbot/builders/wget2-solaris10-i386)
[![Build Status Solaris Sparc](https://buildfarm.opencsw.org/buildbot/png?builder=wget2-solaris10-sparc)](https://buildfarm.opencsw.org/buildbot/builders/wget2-solaris10-sparc)
[![Build Status Solaris SparcV9](https://buildfarm.opencsw.org/buildbot/png?builder=wget2-solaris10-sparcv9)](https://buildfarm.opencsw.org/buildbot/builders/wget2-solaris10-sparcv9)


Wget2 - multithreaded metalink / file / website downloader / spider and library
===============================================================================

This is Wget2.

Designed and written from scratch it requires a C99 and Posix compliant
development environment.

Included is the stand-alone library libwget which provides an interface
to many useful functions used by Wget2.

In many cases Wget2 downloads much faster than Wget1.x due to HTTP zlib
compression, parallel connections and use of If-Modified-Since HTTP header.

HTTP/2 has been implemented.

Wget2 consumes less system and user CPU cycles than Wget1.x.

License
-------

Wget2 is licensed under GPLv3+.

Libwget is licensed under LGPLv3+.

Contact
-------

[Project](https://savannah.gnu.org/projects/wget/)<br>
[Mailing List](https://savannah.gnu.org/mail/?group=wget)<br>
[Bug Tracker](https://savannah.gnu.org/bugs/?group=wget)

Development Status
------------------

Wget2 has already many features that go beyond what Wget1.x provides.<br>

An incomplete list of implemented features:

- TCP Fast Open for plain text *and* for HTTPS
- TLS Session Resumption including persistent session data cache
- TLS False Start (with GnuTLS >= 3.5.0)
- HTTP2 support via nghttp2 and GnuTLS ALPN including streaming/pipelining
- OCSP stapling + OCSP server querying as a fallback (experimental, needs GnuTLS >= 3.3.11)
- Use [libpsl](https://github.com/rockdaboot/libpsl) for cookie domain checking (using Public Suffix List)
- Support link conversion (-k/--convert-links and -K/--backup-converted)
- Support for RFC 6266 compliant Content-Disposition
- RFC 6797 HSTS (HTTP Strict Transport Security)
- Support for bzip2 Content-Encoding / Accept-Encoding compression type
- New Year 2014 gimmick: added support for XZ Content-Encoding / Accept-Encoding compression type
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
- IDN support for international domains
- autotools support
- proxy support
- cookies (session/non-session), detection of supercookies via Mozilla Public Suffix List
  (use the new option --cookie-suffixes <filename>, better: put it into ~/.wgetrc)
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

Some ideas of what could be done next (but contact us via mailing list before you start bigger changes!):

- [EFF HTTPS Everywhere](https://www.eff.org/https-everywhere)
- SSH-style TOFU (Trust On First Use)
- DANE / DNSSEC (waiting for Debian to have libdane from GnuTLS... but that needs libunbound work with GnuTLS, right
  now it only works with OpenSSL.)
- WARC support
- read credentials from secure wallets (e.g. kwallet, firefox, http://sourceforge.net/projects/passwordsafe/)
- [Chromium HSTS domain preload list](http://src.chromium.org/viewvc/chrome/trunk/src/net/http/transport_security_state_static.json)
- respect data-urls
- Streaming (.m3u, etc. formats)
- FTP support
- a progress display
- Documentation docbook with free Serna WYSIWYG/WYMIWYG editor (conversion to texinfo possible)
  and/or with doxygen (API docs embedded into source code)
- plugin technology to plug in user-specific code


Requirements
------------

The following packages are needed to build Wget2:

* autotools (autoconf, autogen, automake, autopoint, libtool)
* pkg-config >= 0.28 (recommended)
* doxygen (for creating the documentation)
* gettext >= 0.18.1
* libz >= 1.2.3 (the distribution may call the package zlib*, eg. zlib1g on Debian)
* liblzma >= 5.1.1alpha (optional, if you want HTTP lzma decompression)
* libbz2 >= 1.0.6 (optional, if you want HTTP bzip2 decompression)
* libgnutls >= 2.10.0
* libidn2 >= 0.9 + libunistring >= 0.9.3 (libidn >= 1.25 if you don't have libidn2)
* flex >= 2.5.35
* libpsl >= 0.5.0
* libnghttp2 >= 1.3.0 (optional, if you want HTTP/2 support)

The versions are recommended, but older versions may also work.


Building from git
-----------------

Download project and prepare sources with

		git clone git://git.savannah.gnu.org/wget/wget2.git
		# or from Gitlab: git clone git@gitlab.com:rockdaboot/wget2.git
		# or from Github: git clone git@github.com:rockdaboot/wget2.git
		cd wget2
		./bootstrap

Build Wget2 with

		./configure
		make

Test the functionality

		make check

Install Wget2 and libwget

		sudo make install (or su -c "make install")

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
Well, you want to valgrind 'wget2' and not the test program itself, right ?

Documentation
-------------

There is no own documentation yet, but Wget2 aims to be Wget1.x compatible.

		wget2 --help

prints the usage and the current set of integrated options.
For more info, see the man pages of Wget1.x.

The Wget2 library API documentation has been started.

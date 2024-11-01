[![Build status](https://gitlab.com/gnuwget/wget2/badges/master/pipeline.svg)](https://gitlab.com/gnuwget/wget2/pipelines)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/wget2.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:wget2)
[![Coverage status](https://gnuwget.gitlab.io/wget2/fuzz-coverage.svg)](https://gnuwget.gitlab.io/wget2/fuzz-coverage)
[![Coverage status](https://gnuwget.gitlab.io/wget2/coverage.svg)](https://gnuwget.gitlab.io/wget2/coverage)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7852/badge.svg)](https://scan.coverity.com/projects/rockdaboot-wget2)

Solaris OpenCSW [![Build Status Solaris amd64](https://buildfarm.opencsw.org/buildbot/png?builder=wget2-solaris10-amd64)](https://buildfarm.opencsw.org/buildbot/builders/wget2-solaris10-amd64)
[![Build Status Solaris i386](https://buildfarm.opencsw.org/buildbot/png?builder=wget2-solaris10-i386)](https://buildfarm.opencsw.org/buildbot/builders/wget2-solaris10-i386)
[![Build Status Solaris Sparc](https://buildfarm.opencsw.org/buildbot/png?builder=wget2-solaris10-sparc)](https://buildfarm.opencsw.org/buildbot/builders/wget2-solaris10-sparc)
[![Build Status Solaris SparcV9](https://buildfarm.opencsw.org/buildbot/png?builder=wget2-solaris10-sparcv9)](https://buildfarm.opencsw.org/buildbot/builders/wget2-solaris10-sparcv9)

# Table of Content
- [GNU Wget2 - Introduction](#GNU-Wget2---Introduction)
- [Features](#Features)
- [Links](#Links)
- [Build Requirements](#Build-Requirements)
- [Downloading and building from tarball](#Downloading-and-building-from-tarball)
- [Building from git](#Building-from-git)
  - [Download project and prepare sources with](#Download-project-and-prepare-sources-with)
  - [Build Wget2 with](#Build-Wget2-with)
  - [In Haiku build Wget2 with](#In-Haiku-build-Wget2-with)
  - [Test the functionality](#Test-the-functionality)
  - [Install Wget2 and libwget](#Install-Wget2-and-libwget)
  - [Build static wget2.exe on GNU/Linux for Windows](#build-static-wget2exe-on-gnulinux-for-windows)
- [License](#License)

# GNU Wget2 - Introduction

GNU Wget2 is the successor of GNU Wget, a file and recursive website downloader.

Designed and written from scratch it wraps around libwget, that provides the basic
functions needed by a web client.

Wget2 works multi-threaded and uses many features to allow fast operation.

In many cases Wget2 downloads much faster than Wget1.x due to HTTP2, HTTP compression,
parallel connections and use of If-Modified-Since HTTP header.

GNU Wget2 is licensed under GPLv3+.

Libwget is licensed under LGPLv3+.


# Features

A non-exhaustive list of features

- Support for HTTP/1.1 and HTTP/2.0 protocol
- [brotli](https://github.com/google/brotli) decompression support (Accept-Encoding: br)
- [zstandard](https://github.com/facebook/zstd) decompression support, RFC8478 (Accept-Encoding: zstd)
- [lzip](https://www.nongnu.org/lzip/) decompression support, (Accept-Encoding: lzip)
- HPKP - HTTP Public Key Pinning (RFC7469) with persistent database
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
- Support scanning RSS 2.0 feeds from local files (`--force-rss -i <filename>`)
- Support scanning RSS 2.0 feeds.
- Support scanning Atom 1.0 feeds from local files (`--force-atom -i <filename>`)
- Support scanning Atom 1.0 feeds.
- Support scanning URLs from local Sitemap XML file (`--force-sitemap -i <filename>`)
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
  (use the new option `--cookie-suffixes <filename>`, better: put it into ~/.wgetrc)
- recursive download of websites with or without spanning hosts
- download of single web pages / resources
- zlib/gzip compressed HTTP/HTTPS downloads (gzip, deflate)
- number of parallel download threads is adjustable
- include directive for config files (wildcards allowed)
- support for keep-alive connections
- included CSS, HTML, XML parser needed for recursive downloads
- gettext support
- HTTPS via libgnutls (and basic WolfSSL support)
- support for Metalink RFC 6249 (Metalink/HTTP: Mirrors and Hashes)
- support for Metalink RFC 5854 (Metalink Download Description Format / .meta4 files)
- support for Metalink 3
- Metalink checksumming via libgnutls
- DNS lookup cache
- IPv4 and IPv6 support
- built and tested on Linux, OSX, OpenBSD, FreeBSD, Solaris, Windows


# Links

[Online Docs](https://gnuwget.gitlab.io/wget2/reference/)

[Mailing List](https://savannah.gnu.org/mail/?group=wget)

[Bug Tracker](https://gitlab.com/gnuwget/wget2/issues)

[Development](https://gitlab.com/gnuwget/wget2)

[Code Coverage](https://gnuwget.gitlab.io/wget2/coverage/)

[Fuzz Code Coverage](https://gnuwget.gitlab.io/wget2/fuzz-coverage/)


# Build Requirements

The following packages are needed to build the software

* autotools (autoconf, autogen, automake, autopoint, libtool)
* python (recommended for faster bootstrap)
* rsync
* tar
* makeinfo (part of texinfo)
* pkg-config >= 0.28 (recommended)
* doxygen (for creating the documentation)
* pandoc (for creating the wget2 man page)
* gettext >= 0.18.2
* libiconv (needed for IRI and IDN support)
* libz >= 1.2.3 (the distribution may call the package zlib*, eg. zlib1g on Debian)
* liblzma >= 5.1.1alpha (optional, if you want HTTP lzma decompression)
* libbz2 >= 1.0.6 (optional, if you want HTTP bzip2 decompression)
* libbrotlidec/libbrotli >= 1.0.0 (optional, if you want HTTP brotli decompression)
* libzstd >= 1.3.0 (optional, if you want HTTP zstd decompression)
* libgnutls (3.3, 3.5 or 3.6)
* libidn2 >= 0.14 (libidn >= 1.25 if you don't have libidn2)
* flex >= 2.5.35
* libpsl >= 0.5.0
* libnghttp2 >= 1.3.0 (optional, if you want HTTP/2 support)
* libmicrohttpd >= 0.9.51 (optional, if you want to run the test suite)
* lzip (optional, if you want to build distribution tarballs)
* lcov (optional, for coverage reports)
* libgpgme >= 0.4.2 (optional, for automatic signature verification)
* libpcre | libpcre2 (optional, for filtering by PCRE|PCRE2 regex)
* libhsts (optional, to support HSTS preload lists)
* libwolfssl (optional, to support WolfSSL instead of GnuTLS)

The versions are recommended, but older versions may also work.


# Downloading and building from tarball

		wget https://gnuwget.gitlab.io/wget2/wget2-latest.tar.gz
		tar xf wget2-latest.tar.gz
		cd wget2-*
		./configure
		make
		make check
		sudo make install


# Building from git

### Download project and prepare sources with

		git clone https://gitlab.com/gnuwget/wget2.git
		cd wget2
		./bootstrap
		# on shell failure try 'bash ./bootstrap'

### Build Wget2 with

		./configure
		make

### In Haiku build Wget2 with

        setarch x86
        ./configure --prefix=/boot/home/config/non-packaged
        rm /boot/home/config/non-packaged/wget2 && mv /boot/home/config/non-packaged/wget2_noinstall /boot/home/config/non-packaged/wget2

### Test the functionality

		make check

### Install Wget2 and libwget

		sudo make install (or su -c "make install")

### Build static wget2.exe on GNU/Linux for Windows

		(cd contrib; docker build -t wget2/static -f Dockerfile.win32.static .)
		docker run --rm -v $PWD:/tmp wget2/static cp /usr/local/wget2/src/wget2.exe /tmp
		# now you have `wget2.exe` with debug symbols in your current directory
		# optional: remove debug symbols with
		strip wget2.exe
		# optional: pack executable
		upx wget2.exe

# License

Copyright (C) 2015-2024 Free Software Foundation, Inc.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

A copy of the GNU General Public License can be found in the file LICENSE
in the top directory of the official source distribution. The license is
also available in several formats through the World Wide Web, or
via http://www.gnu.org/licenses/licenses.html#GPL .

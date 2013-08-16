Mget - multithreaded metalink/file/website downloader and library
=================================================================

This is a Wget-like tool and library written in C.

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

Development Status
------------------

Mget is still in alpha stage but is already useful.<br>
Many Wget options are already implemented, but some are still missing.

The basic functionality is implemented, like:

- new option --secure-protocol=secure to have TLS only plus forcing Perfect Forward Secrecy (PFS)
- use TCP Fast Open if available
- IDN support for international domains
- autotools support
- proxy support
- cookies (session/non-session), detection of supercookies via Mozilla Public Suffix List
  (use the new option --cookie-suffixes <filename>, better: put it into ~/.mgetrc)
- respect cookie public suffix list http://publicsuffix.org/list/
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
- compiled and tested with gcc 4.7.1 and clang 3.1.1
- tested regularly with static analysis tools
- compiled and linked with hardening options proposed by the Debian project

Anybody should feel free to contribute ideas, opinions, knowledge, code, tests, etc.

Not yet implemented
-------------------

The following is just a quick list of ideas and todos.<br>
The mid-range goal is to come as close to Wget, that Wget's units test work for Mget.

This is next on my list:

- use [gtk-doc-tools](http://developer.gnome.org/gtk-doc-manual/unstable/settingup.html.en) for documentation.<br>
  I want the docs stay with the code: already tested Doxygen, but the man page support seems broken/orphaned.
- respect /robots.txt "Robot Exclusion Standard" and <META name="robots" ...>
- http authentication (basic & digest RFC 2617) [done and working, but some optimizing needed]
- WARC support
- RFC 6797 HSTS (HTTP Strict Transport Security)
  [Chromium HSTS domain list](https://src.chromium.org/viewvc/chrome/trunk/src/net/base/transport_security_state_static.json)
- read credentials from secure wallets (e.g. kwallet, firefox, maybe an own tool ?)
- compression on TLS/SSL layer (non-standard GnuTLS extension)
- request pipelining (using client cookies)
- SPDY protocol
- respect data-urls
- Atom / RSS / Podcast / Streaming (.m3u, etc. formats)
- ICEcast support
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
* gtk-doc-tools (when creating the HTML documentation)
* xsltproc (when creating man pages)
* gettext >= 0.18.1
* libz >= 1.2.3
* libgnutls >= 2.4.2
* libidn >= 1.25
* flex >= 2.5.35

The versions are recommended, but older versions are supposed to work.


Building from git
-----------------

Download project and prepare sources with

		git clone http://github.com/rockdaboot/mget
		./autogen.sh

Build Mget with

		./configure
		make

Test the functionality (sorry, right now under heavy development)

		make check

Install Mget and libmget

		sudo make install (or su -c "make install")

To create Mget HTML documentation

		./configure --enable-gtk-doc
		make

To create Mget HTML documentation and man pages (not functional right now)

		./configure --enable-gtk-doc --enable-man
		make

Documentation
-------------

There is no own documentation yet, but Mget aims to be Wget1.14 compatible.

		mget --help

prints the usage and the current set of integrated options.
For more info, see the man pages of Wget.

My idea is to use the free Serna WYSIWYG/WYMIWYG editor for documentation.
It creates docbook format which can be converted into texinfo format.
And it opens the documentation process to almost any volunteers without
texinfo knowledge.

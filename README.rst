Mget - multithreaded metalink/file/website downloader
=====================================================

This is an experimental wget-like tool written in C.

Designed and written from scratch it requires a C99 and Posix compliant
development environment.

The originally purpose was to help out on wget2 development (refactoring,
modern and clean code, new technology, new design).

In many cases Mget downloads much faster than Wget due to HTTP zlib
compression and parallel connections.
It comsumes less sys and user CPU cycles due to larger buffers and
buffer recycling.

License
-------

Mget is licensed under GPLv3.

Development Status
------------------

Mget is in alpha stage.
You might encounter lot's of bugs and missing features.
So, for now (10.08.2012), don't use it for production !

The basic functionality is implemented, like:
- recursive download of websites with or without spanning hosts
- download of single web pages / resources
- zlib/gzip compressed HTTP/HTTPS downloads
- number of parallel download threads is adjustable
- include directive for config files (wildcards allowed)
- support for keep-alive connections
- included CSS, HTML, XML parser needed for recursive downloads
- gettext support
- HTTPS via libgnutls
- support for Metalink RFC 6249 (Metalink/HTTP: Mirrors and Hashes)
- support for Metalink RFC 5854 (Metalink Download Description Format / .meta4 files)
- Metalink checksumming via libgnutls
- tested on Debian SID amd64 and OpenBSD 5.0
- compiled and tested with gcc 4.7.1 and clang 3.1.1
- tested regularly with static analysis tools
- compiled and linked with hardening options proposed by the Debian project
- plugin technology to plug in user-specific code

Anybody should feel free to contribute ideas, opinions, knowledge (docs, code,
 autotools, etc.).

No yet implemented
------------------

The following is just a quick list of ideas and todos.
I personally like to experiment with new stuff (new to wget), so
request pipelining and SPDY protocol are my favorites.

- DNS lookup cache
- respect /robots.txt "Robot Exclusion Standard"
- proxy support
- server cookie stuff
- a --sync option / respect page expiry dates / only download changed pages
- respect data-urls
- http authentication (basic & digest RFC 2617)
- request pipelining (using client cookies)
- SPDY protocol
- Atom / RSS / Podcast / Streaming (.m3u, etc. formats)
- ICEcast support
- ftp support
- https with openssl
- a progress display
- Documentation docbook with free Serna WYSIWYG/WYMIWYG editor (conversion to texinfo possible)
- to implement Content-Encoding 'compress' and 'deflate' I need a server supporting these
- many easy-to-implement wget options/features


Requirements
------------

The following packages are needed to build Mget:

* libz >= 1.2.3
* libgnutls >= 2.4.2
* flex >= 2.5.35

The versions are recommended, but older version like on OpenBSD 5.0
are supposed to work.


Building from git
-----------------

Build mget with just::

    $ make

Have a look into Makefile / BSDMakefile to change some defines.

Documentation
-------------

There is no documentation yet.

    $ mget --help

prints the usage and current set of options

My idea is to use the free Serna WYSIWYG/WYMIWYG editor for documentation.
It creates docbook format which can be converted into texinfo format.
And it opens the documentation process to almost any volunteers without
texinfo knowledge.

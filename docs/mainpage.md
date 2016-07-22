# GNU Wget2

The wget2 utility is a recursive, multi-threaded HTTP(S) downloader.
It is built around [libwget](#libwget).

Wget2 is partially compatible with GNU Wget but offers new features and options while
some of the fancier options have been dropped resp. have not been ported yet.

[wget2 manual](wget2_manual.md)

## GNU libwget

Libwget offers an API for easy building of network applications.

[API overview](modules.html)


## Contact / Community

* [Project](https://savannah.gnu.org/projects/wget/)
* [Mailing List](https://savannah.gnu.org/mail/?group=wget)
* [Bug Tracker](https://savannah.gnu.org/bugs/?group=wget)


## Build requirements

The following packages are needed to build the Wget2 project:

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


## Building from git

Download project and prepare sources with

		git clone git://git.savannah.gnu.org/wget/wget2.git
		# or from Gitlab: git clone git@gitlab.com:rockdaboot/wget2.git
		# or from Github: git clone git@github.com:rockdaboot/wget2.git
		cd wget2
		./bootstrap

Build with

		./configure
		make

Test the functionality

		make check

Install wget2 and libwget

		sudo make install (or su -c "make install")


## License

Wget2 is licensed under GPLv3+.

Libwget is licensed under LGPLv3+.

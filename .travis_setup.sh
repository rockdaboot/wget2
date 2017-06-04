#!/bin/bash

if [[ "$TRAVIS_OS_NAME" = "osx" ]]; then
	brew update
	brew install gnutls
	brew install nettle
	brew outdated autoconf || brew upgrade autoconf
	brew outdated automake || brew upgrade automake
	brew outdated libtool || brew upgrade libtool
	brew install doxygen
	brew outdated gettext || brew upgrade gettext
	brew install flex
	brew install libidn
	brew install xz
	brew install lbzip2
	brew install lzip
	brew install libgcrypt
	brew link --force gettext
elif [[ "$TRAVIS_OS_NAME" = "linux" ]]; then
	# Install Libmicrohttpd from source
	sudo apt-get -y install wget
	wget http://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-0.9.55.tar.gz
	tar zxf libmicrohttpd-0.9.55.tar.gz && cd libmicrohttpd-0.9.55/
	./configure --prefix=/usr && make -j$(nproc) && sudo make install
	pip install --user cpp-coveralls
fi

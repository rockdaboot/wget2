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
	brew link --force gettext
elif [[ "$TRAVIS_OS_NAME" = "linux" ]]; then
	pip install --user cpp-coveralls
fi

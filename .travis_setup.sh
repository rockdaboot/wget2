#!/bin/bash

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
	brew update
	brew install gnutls
	brew install nettle
	brew outdated autoconf || brew upgrade autoconf
	brew outdated automake || brew upgrade automake
	brew outdated libtool || brew upgrade libtool
	brew install doxygen
	brew outdated gettext || brew upgrade gettext
	# brew install valgrind
	brew install flex
	brew install libidn
	brew install xz
	brew install lbzip2
	brew install graphviz
	brew install lcov
	brew outdated pyenv || brew upgrade pyenv
	eval "$(pyenv init -)"
	pyenv install 2.7.6
	pyenv global 2.7.6
	pyenv rehash
	pip install cpp-coveralls
	pyenv rehash
	brew link --force gettext
elif [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
	pip install --user cpp-coveralls
fi

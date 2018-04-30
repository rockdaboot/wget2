#!/bin/sh -e
#
# gcc70: NetBSD 5.1 (as of 13.4.2018)

PROJECTDIR="$PWD"

PREFIX=x86_64-linux-gnu
export INSTALLDIR="$PWD/$PREFIX"
export PKG_CONFIG_PATH=$INSTALLDIR/lib/pkgconfig:/usr/$PREFIX/lib/pkgconfig
export CPPFLAGS="-I$INSTALLDIR/include"
export LDFLAGS="-L$INSTALLDIR/lib"

# Install Libmicrohttpd from source
#rm -rf libmicrohttpd-*
#wget --no-check-certificate https://ftpmirror.gnu.org/libmicrohttpd/libmicrohttpd-latest.tar.gz
#tar xfz libmicrohttpd-latest.tar.gz
#cd libmicrohttpd-[0-9]*
#./configure --prefix=$INSTALLDIR --disable-doc --disable-examples --enable-shared
#make -j2
#make install
#cd ..

# Test Wget2
cd wget2-[0-9]*
./configure --prefix=$INSTALLDIR --disable-doc
make -j2
make -j2 check

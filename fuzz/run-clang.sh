# Copyright(c) 2017 Free Software Foundation, Inc.
#
# This file is part of libwget.
#
# Libwget is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Libwget is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with libwget.  If not, see <https://www.gnu.org/licenses/>.

if test -z "$1"; then
	echo "Usage: $0 <fuzzer target>"
	echo "Example: $0 libwget_robots_parse_fuzzer"
	exit 1
fi

fuzzer=$1
workers=$(($(nproc) - 1))
jobs=$workers

clang-5.0 \
 $CFLAGS -I../include/wget -I.. \
 ${fuzzer}.c -o ${fuzzer} \
 -Wl,-Bstatic ../libwget/.libs/libwget.a -lFuzzer \
 -Wl,-Bdynamic -lgnutls -lidn2 -lunistring -lpsl -lclang-5.0 -lstdc++

# create directory for NEW test corpora (covering new areas of code)
mkdir -p ${fuzzer}.new

if test -f ${fuzzer}.dict; then
  ./${fuzzer} -dict=${fuzzer}.dict ${fuzzer}.new ${fuzzer}.in -jobs=$jobs -workers=$workers
else
  ./${fuzzer} ${fuzzer}.new ${fuzzer}.in -jobs=$jobs -workers=$workers
fi

exit 0

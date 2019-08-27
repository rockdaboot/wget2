# Copyright(c) 2018-2019 Free Software Foundation, Inc.
#
# This file is part of GNU Wget.
#
# Wget is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Wget is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Wget.  If not, see <https://www.gnu.org/licenses/>.

CURL_SOURCE=https://github.com/curl/curl.git
CURL_OPTIONS="-s -o/dev/null --cert-status"
CURL_BIN="./src/curl"

CURL_BUILD() {
	./buildconf
	./configure -q --disable-manual --with-gnutls
	make -s "-j$(nproc)"
}

CURL_VERSION() {
	${CURL_BIN} --version | head -1 | cut -d' ' -f2
}

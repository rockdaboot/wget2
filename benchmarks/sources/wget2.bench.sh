# Copyright (c) 2018-2019 Free Software Foundation, Inc.
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

WGET2_SOURCE=https://gitlab.com/gnuwget/wget2.git
WGET2_OPTIONS="-q --no-config -O/dev/null"
WGET2_BIN="./src/wget2_noinstall"

WGET2_BUILD() {
	./bootstrap --skip-po
	./configure -q --disable-doc
	make -s "-j$(nproc)"
}

WGET2_VERSION() {
	${WGET2_BIN} --version | head -1 | cut -d' ' -f3
}

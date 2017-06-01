# Copyright (C) 2016 Red Hat, Inc.
#
# This file is part of Wget2.
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

CC?=afl-clang-fast
CFLAGS?=-g -O2 -Wall -Wextra
COMMON=-I../lib/ -L../libwget/.libs -Wl,-rpath=../libwget/.libs -lwget

TESTS = \
 libwget_xml_parse_buffer_fuzzer \
 libwget_memtohex_fuzzer \
 libwget_robots_parse_fuzzer \
 libwget_bar_fuzzer \
 libwget_metalink_parse_fuzzer

all: $(TESTS)

%: %.cc
	AFL_HARDEN=1 $(CC) $(CFLAGS) main.c $^ $(COMMON) -o $@ -lstdc++

fuzz-coverage: $(TESTS)
	find . -name '*_fuzzer' -exec ./coverage.sh '{}' ';'

clean:
	rm -f $(TESTS) *.gcda *.gcov

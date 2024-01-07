/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Dummy libraries for testing dynamic loading abstraction
 *
 */

#include <config.h>

#include <string.h>

#include <wget.h> //For WGET_EXPORT

#define stringify2(x) #x
#define stringify(x) stringify2(x)
#define concat2(x, y) x ## y
#define concat(x, y) concat2(x, y)

WGET_EXPORT void dl_test_write_param(char *buf, size_t len);
WGET_EXPORT void concat(dl_test_fn_, PARAM)(char *buf, size_t len);

void dl_test_write_param(char *buf, size_t len)
{
	wget_strlcpy(buf, stringify(PARAM), len);
}

void concat(dl_test_fn_, PARAM)(char *buf, size_t len)
{
	wget_strlcpy(buf, stringify(PARAM), len);
}

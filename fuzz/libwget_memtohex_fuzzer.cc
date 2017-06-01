/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
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
 */

#include "../config.h"

#include <assert.h> // assert
#include <stdint.h> // uint8_t
#include <stdlib.h> // malloc, free
#include <string.h> // memcpy

#include "wget.h"

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char dst1[1];
	char dst2[2];
	char dst3[3];
	char dst4[4];
	char dst5[8];
	char *dst = (char *) malloc(size * 2 + 1);

	assert(dst != NULL);

	wget_memtohex(NULL, 0, NULL, 0);
	wget_memtohex(data, size, dst1, sizeof(dst1));
	wget_memtohex(data, size, dst2, sizeof(dst2));
	wget_memtohex(data, size, dst3, sizeof(dst3));
	wget_memtohex(data, size, dst4, sizeof(dst4));
	wget_memtohex(data, size, dst5, sizeof(dst5));
	wget_memtohex(data, size, dst, size * 2 + 1);

	free(dst);

	return 0;
}

/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for http decompression routines
 *
 * Changelog
 * 20.06.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_DECOMPRESSOR_H
#define _MGET_DECOMPRESSOR_H

#include <stddef.h>

typedef struct DECOMPRESSOR DECOMPRESSOR;

enum {
	content_encoding_identity,
	content_encoding_gzip,
	content_encoding_deflate
};

DECOMPRESSOR
	*decompress_open(int encoding,
						  int (*put_data)(void *context, const char *data, size_t length),
						  void *context);
void
	decompress_close(DECOMPRESSOR *dc);
int
	decompress(DECOMPRESSOR *dc, char *src, size_t srclen);

#endif /* _MGET_DECOMPRESSOR_H */

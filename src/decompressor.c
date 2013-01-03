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
 * HTTP decompression routines
 *
 * Changelog
 * 20.06.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include <libmget.h>

#include "xalloc.h"
#include "log.h"
#include "decompressor.h"

struct MGET_DECOMPRESSOR {
	union {
		z_stream
		strm;
	} extra;
	int
		(*decompress)(MGET_DECOMPRESSOR *dc, char *src, size_t srclen),
		(*put_data)(void *context, const char *data, size_t length); // decompressed data goes here
	void
		(*exit)(MGET_DECOMPRESSOR *dc),
		*context; // given to put_data()
	char
		encoding;
};

static int gzip_init(z_stream *strm)
{
	memset(strm, 0, sizeof(*strm));

	// +16: decode gzip format only
	// +32: decode gzip and zlib (autodetect)
	if (inflateInit2(strm, 15 + 32) != Z_OK) {
		err_printf(_("Failed to init gzip decompression\n"));
		return -1;
	}

	return 0;
}

static int gzip_decompress(MGET_DECOMPRESSOR *dc, char *src, size_t srclen)
{
	z_stream *strm;
	char dst[10240];
	int status;

	if (!srclen) {
		// special case to avoid decompress errors
		if (dc->put_data)
			dc->put_data(dc->context, "", 0);

		return 0;
	}

	strm = &dc->extra.strm;
	strm->next_in = (unsigned char *)src;
	strm->avail_in = srclen;

	do {
		strm->next_out = (unsigned char *)dst;
		strm->avail_out = sizeof(dst);

		status = inflate(strm, Z_SYNC_FLUSH);
		if ((status == Z_OK || status == Z_STREAM_END) && strm->avail_out<sizeof(dst)) {
			if (dc->put_data)
				dc->put_data(dc->context, dst, sizeof(dst) - strm->avail_out);
		}
	} while (status == Z_OK && !strm->avail_out);

	if (status == Z_OK || status == Z_STREAM_END)
		return 0;

	err_printf(_("Failed to uncompress gzip stream (%d)\n"), status);
	return -1;
}

static void gzip_exit(MGET_DECOMPRESSOR *dc)
{
	int status;

	if ((status = inflateEnd(&dc->extra.strm)) != Z_OK) {
		err_printf(_("Failed to close gzip stream (%d)\n"), status);
	}
}

static int deflate_init(z_stream *strm)
{
	memset(strm, 0, sizeof(*strm));

	// -15: decode raw deflate data
	if (inflateInit2(strm, -15) != Z_OK) {
		err_printf(_("Failed to init deflate decompression\n"));
		return -1;
	}

	return 0;
}

static int identity(MGET_DECOMPRESSOR *dc, char *src, size_t srclen)
{
	if (dc->put_data)
		dc->put_data(dc->context, src, srclen);

	return 0;
}

MGET_DECOMPRESSOR *decompress_open(int encoding,
	int (*put_data)(void *context, const char *data, size_t length),
	void *context)
{
	MGET_DECOMPRESSOR *dc = xcalloc(1, sizeof(MGET_DECOMPRESSOR));
	int rc = 0;

	if (encoding == content_encoding_gzip) {
		if ((rc = gzip_init(&dc->extra.strm)) == 0) {
			dc->decompress = gzip_decompress;
			dc->exit = gzip_exit;
		}
	} else if (encoding == content_encoding_deflate) {
		if ((rc = deflate_init(&dc->extra.strm)) == 0) {
			dc->decompress = gzip_decompress;
			dc->exit = gzip_exit;
		}
	} else {
		// identity
		dc->decompress = identity;
	}

	if (rc) {
		xfree(dc);
		return NULL;
	}

	dc->encoding = (char)encoding;
	dc->put_data = put_data;
	dc->context = context;
	return dc;
}

void decompress_close(MGET_DECOMPRESSOR *dc)
{
	if (dc) {
		if (dc->exit)
			dc->exit(dc);
		xfree(dc);
	}
}

int decompress(MGET_DECOMPRESSOR *dc, char *src, size_t srclen)
{
	if (dc) {
		return dc->decompress(dc, src, srclen);
	}

	return 0;
}

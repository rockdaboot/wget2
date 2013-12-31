/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * HTTP decompression routines
 *
 * Changelog
 * 20.06.2012  Tim Ruehsen  created
 * 31.12.2013  Tim Ruehsen  added LZMA decompression
 *
 * see https://wiki.mozilla.org/LZMA2_Compression
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#if WITH_ZLIB
#include <zlib.h>
#endif

#if WITH_LZMA
#include <lzma.h>
#endif

#include <libmget.h>
#include "private.h"

struct _MGET_DECOMPRESSOR {
#if WITH_ZLIB
	z_stream
		z_strm;
#endif
#if WITH_LZMA
	lzma_stream
		lzma_strm;
#endif

	int
		(*decompress)(MGET_DECOMPRESSOR *dc, char *src, size_t srclen),
		(*put_data)(void *context, const char *data, size_t length); // decompressed data goes here
	void
		(*exit)(MGET_DECOMPRESSOR *dc),
		*context; // given to put_data()
	char
		encoding;
};

#if WITH_ZLIB
static int gzip_init(z_stream *strm)
{
	memset(strm, 0, sizeof(*strm));

	// +16: decode gzip format only
	// +32: decode gzip and zlib (autodetect)
	if (inflateInit2(strm, 15 + 32) != Z_OK) {
		error_printf(_("Failed to init gzip decompression\n"));
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

	strm = &dc->z_strm;
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

	error_printf(_("Failed to uncompress gzip stream (%d)\n"), status);
	return -1;
}

static void gzip_exit(MGET_DECOMPRESSOR *dc)
{
	int status;

	if ((status = inflateEnd(&dc->z_strm)) != Z_OK) {
		error_printf(_("Failed to close gzip stream (%d)\n"), status);
	}
}

static int deflate_init(z_stream *strm)
{
	memset(strm, 0, sizeof(*strm));

	// -15: decode raw deflate data
	if (inflateInit2(strm, -15) != Z_OK) {
		error_printf(_("Failed to init deflate decompression\n"));
		return -1;
	}

	return 0;
}
#endif // WITH_ZLIB

#if WITH_LZMA
static int lzma_init(lzma_stream *strm)
{
	memset(strm, 0, sizeof(*strm));

//	if (lzma_stream_decoder(strm, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED) != LZMA_OK) {
	if (lzma_stream_decoder(strm, UINT64_MAX, 0) != LZMA_OK) {
		error_printf(_("Failed to init LZMA decompression\n"));
		return -1;
	}

	return 0;
}

static int lzma_decompress(MGET_DECOMPRESSOR *dc, char *src, size_t srclen)
{
	lzma_stream *strm;
	char dst[10240];
	int status;

	if (!srclen) {
		// special case to avoid decompress errors
		if (dc->put_data)
			dc->put_data(dc->context, "", 0);

		return 0;
	}

	strm = &dc->lzma_strm;
	strm->next_in = (unsigned char *)src;
	strm->avail_in = srclen;

	do {
		strm->next_out = (unsigned char *)dst;
		strm->avail_out = sizeof(dst);

		status = lzma_code(strm, LZMA_RUN);
		if ((status == LZMA_OK || status == LZMA_STREAM_END) && strm->avail_out<sizeof(dst)) {
			if (dc->put_data)
				dc->put_data(dc->context, dst, sizeof(dst) - strm->avail_out);
		}
	} while (status == LZMA_OK && !strm->avail_out);

	if (status == Z_OK || status == Z_STREAM_END)
		return 0;

	error_printf(_("Failed to uncompress LZMA stream (%d)\n"), status);
	return -1;
}

static void lzma_exit(MGET_DECOMPRESSOR *dc)
{
	lzma_end(&dc->lzma_strm);
}
#endif // WITH_LZMA

static int identity(MGET_DECOMPRESSOR *dc, char *src, size_t srclen)
{
	if (dc->put_data)
		dc->put_data(dc->context, src, srclen);

	return 0;
}

MGET_DECOMPRESSOR *mget_decompress_open(int encoding,
	int (*put_data)(void *context, const char *data, size_t length),
	void *context)
{
	MGET_DECOMPRESSOR *dc = xcalloc(1, sizeof(MGET_DECOMPRESSOR));
	int rc = 0;

	if (encoding == mget_content_encoding_gzip) {
#if WITH_ZLIB
		if ((rc = gzip_init(&dc->z_strm)) == 0) {
			dc->decompress = gzip_decompress;
			dc->exit = gzip_exit;
		}
#endif
	} else if (encoding == mget_content_encoding_deflate) {
#if WITH_ZLIB
		if ((rc = deflate_init(&dc->z_strm)) == 0) {
			dc->decompress = gzip_decompress;
			dc->exit = gzip_exit;
		}
#endif
	} else if (encoding == mget_content_encoding_lzma) {
#if WITH_LZMA
		if ((rc = lzma_init(&dc->lzma_strm)) == 0) {
			dc->decompress = lzma_decompress;
			dc->exit = lzma_exit;
		}
#endif
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

void mget_decompress_close(MGET_DECOMPRESSOR *dc)
{
	if (dc) {
		if (dc->exit)
			dc->exit(dc);
		xfree(dc);
	}
}

int mget_decompress(MGET_DECOMPRESSOR *dc, char *src, size_t srclen)
{
	if (dc) {
		return dc->decompress(dc, src, srclen);
	}

	return 0;
}

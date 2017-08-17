/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2017 Free Software Foundation, Inc.
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
 * HTTP decompression routines
 *
 * Changelog
 * 20.06.2012  Tim Ruehsen  created
 * 31.12.2013  Tim Ruehsen  added XZ / LZMA decompression
 * 02.01.2014  Tim Ruehsen  added BZIP2 decompression
 * 24.02.2017  Tim Ruehsen  added Brotli decompression
 *
 * References
 *   https://en.wikipedia.org/wiki/HTTP_compression
 *   https://wiki.mozilla.org/LZMA2_Compression
 *   https://groups.google.com/forum/#!topic/mozilla.dev.platform/CBhSPWs3HS8
 *   https://github.com/google/brotli
 */

#include <config.h>

#include <stdio.h>
#include <string.h>

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#ifdef WITH_BZIP2
#include <bzlib.h>
#endif

#ifdef WITH_LZMA
#include <lzma.h>
#endif

#ifdef WITH_BROTLIDEC
#include <brotli/decode.h>
#endif

#include <wget.h>
#include "private.h"

typedef int (*wget_decompressor_decompress_t)(wget_decompressor_t *dc, char *src, size_t srclen);
typedef void (*wget_decompressor_exit_t)(wget_decompressor_t *dc);

struct _wget_decompressor_st {
#ifdef WITH_ZLIB
	z_stream
		z_strm;
#endif
#ifdef WITH_LZMA
	lzma_stream
		lzma_strm;
#endif
#ifdef WITH_BZIP2
	bz_stream
		bz_strm;
#endif
#ifdef WITH_BROTLIDEC
	BrotliDecoderState
		*brotli_strm;
#endif

	wget_decompressor_sink_t
		sink; // decompressed data goes here
	wget_decompressor_error_handler_t
		error_handler; // called on error
	wget_decompressor_decompress_t
		decompress;
	wget_decompressor_exit_t
		exit;
	void
		*context; // given to sink()
	char
		encoding;
};

#ifdef WITH_ZLIB
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

static int gzip_decompress(wget_decompressor_t *dc, char *src, size_t srclen)
{
	z_stream *strm;
	char dst[10240];
	int status;

	if (!srclen) {
		// special case to avoid decompress errors
		if (dc->sink)
			dc->sink(dc->context, "", 0);

		return 0;
	}

	strm = &dc->z_strm;
	strm->next_in = (unsigned char *) src;
	strm->avail_in = (unsigned int) srclen;

	do {
		strm->next_out = (unsigned char *) dst;
		strm->avail_out = sizeof(dst);

		status = inflate(strm, Z_SYNC_FLUSH);
		if ((status == Z_OK || status == Z_STREAM_END) && strm->avail_out < sizeof(dst)) {
			if (dc->sink)
				dc->sink(dc->context, dst, sizeof(dst) - strm->avail_out);
		}
	} while (status == Z_OK && !strm->avail_out);

	if (status == Z_OK || status == Z_STREAM_END)
		return 0;

	error_printf(_("Failed to uncompress gzip stream (%d)\n"), status);
	return -1;
}

static void gzip_exit(wget_decompressor_t *dc)
{
	int status;

	if ((status = inflateEnd(&dc->z_strm)) != Z_OK) {
		error_printf(_("Failed to close gzip stream (%d)\n"), status);
	}
}

static int deflate_init(z_stream *strm)
{
	memset(strm, 0, sizeof(*strm));

	if (inflateInit(strm) != Z_OK) {
		error_printf(_("Failed to init deflate decompression\n"));
		return -1;
	}

	return 0;
}
#endif // WITH_ZLIB

#ifdef WITH_LZMA
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

static int lzma_decompress(wget_decompressor_t *dc, char *src, size_t srclen)
{
	lzma_stream *strm;
	char dst[10240];
	int status;

	if (!srclen) {
		// special case to avoid decompress errors
		if (dc->sink)
			dc->sink(dc->context, "", 0);

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
			if (dc->sink)
				dc->sink(dc->context, dst, sizeof(dst) - strm->avail_out);
		}
	} while (status == LZMA_OK && !strm->avail_out);

	if (status == LZMA_OK || status == LZMA_STREAM_END)
		return 0;

	error_printf(_("Failed to uncompress LZMA stream (%d)\n"), status);
	return -1;
}

static void lzma_exit(wget_decompressor_t *dc)
{
	lzma_end(&dc->lzma_strm);
}
#endif // WITH_LZMA

#ifdef WITH_BROTLIDEC
static int brotli_init(BrotliDecoderState **strm)
{
	if ((*strm = BrotliDecoderCreateInstance(NULL, NULL, NULL)) == NULL) {
		error_printf(_("Failed to init Brotli decompression\n"));
		return -1;
	}

	return 0;
}

static int brotli_decompress(wget_decompressor_t *dc, char *src, size_t srclen)
{
	BrotliDecoderState *strm;
	BrotliDecoderResult status;
	uint8_t dst[10240];
	size_t available_in, available_out;
	const uint8_t *next_in;
	uint8_t *next_out;

	if (!srclen) {
		// special case to avoid decompress errors
		if (dc->sink)
			dc->sink(dc->context, "", 0);

		return 0;
	}

	strm = dc->brotli_strm;
	next_in = (uint8_t *)src;
	available_in = srclen;

	do {
		next_out = (unsigned char *)dst;
		available_out = sizeof(dst);

		status = BrotliDecoderDecompressStream(strm, &available_in, &next_in, &available_out, &next_out, NULL);
		if (available_out != sizeof(dst)) {
			if (dc->sink)
				dc->sink(dc->context, (char *)dst, sizeof(dst) - available_out);
		}
	} while (status == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);

	if (status == BROTLI_DECODER_RESULT_SUCCESS || status == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT)
		return 0;

	BrotliDecoderErrorCode err = BrotliDecoderGetErrorCode(strm);
	error_printf(_("Failed to uncompress Brotli stream (%u): %s\n"), status, BrotliDecoderErrorString(err));

	return -1;
}

static void brotli_exit(wget_decompressor_t *dc)
{
	BrotliDecoderDestroyInstance(dc->brotli_strm);
}
#endif // WITH_BROTLIDEC

#ifdef WITH_BZIP2
static int bzip2_init(bz_stream *strm)
{
	memset(strm, 0, sizeof(*strm));

	if (BZ2_bzDecompressInit(strm, 0, 0) != BZ_OK) {
		error_printf(_("Failed to init bzip2 decompression\n"));
		return -1;
	}

	return 0;
}

static int bzip2_decompress(wget_decompressor_t *dc, char *src, size_t srclen)
{
	bz_stream *strm;
	char dst[10240];
	int status;

	if (!srclen) {
		// special case to avoid decompress errors
		if (dc->sink)
			dc->sink(dc->context, "", 0);

		return 0;
	}

	strm = &dc->bz_strm;
	strm->next_in = src;
	strm->avail_in = (unsigned int) srclen;

	do {
		strm->next_out = dst;
		strm->avail_out = sizeof(dst);

		status = BZ2_bzDecompress(strm);
		if ((status == BZ_OK || status == BZ_STREAM_END) && strm->avail_out<sizeof(dst)) {
			if (dc->sink)
				dc->sink(dc->context, dst, sizeof(dst) - strm->avail_out);
		}
	} while (status == BZ_OK && !strm->avail_out);

	if (status == BZ_OK || status == BZ_STREAM_END)
		return 0;

	error_printf(_("Failed to uncompress bzip2 stream (%d)\n"), status);
	return -1;
}

static void bzip2_exit(wget_decompressor_t *dc)
{
	BZ2_bzDecompressEnd(&dc->bz_strm);
}
#endif // WITH_BZIP2

static int identity(wget_decompressor_t *dc, char *src, size_t srclen)
{
	if (dc->sink)
		dc->sink(dc->context, src, srclen);

	return 0;
}

wget_decompressor_t *wget_decompress_open(int encoding,
	wget_decompressor_sink_t sink,
	void *context)
{
	wget_decompressor_t *dc = xcalloc(1, sizeof(wget_decompressor_t));
	int rc = 0;

	if (encoding == wget_content_encoding_gzip) {
#ifdef WITH_ZLIB
		if ((rc = gzip_init(&dc->z_strm)) == 0) {
			dc->decompress = gzip_decompress;
			dc->exit = gzip_exit;
		}
#endif
	} else if (encoding == wget_content_encoding_deflate) {
#ifdef WITH_ZLIB
		if ((rc = deflate_init(&dc->z_strm)) == 0) {
			dc->decompress = gzip_decompress;
			dc->exit = gzip_exit;
		}
#endif
	} else if (encoding == wget_content_encoding_bzip2) {
#ifdef WITH_BZIP2
		if ((rc = bzip2_init(&dc->bz_strm)) == 0) {
			dc->decompress = bzip2_decompress;
			dc->exit = bzip2_exit;
		}
#endif
	} else if (encoding == wget_content_encoding_lzma) {
#ifdef WITH_LZMA
		if ((rc = lzma_init(&dc->lzma_strm)) == 0) {
			dc->decompress = lzma_decompress;
			dc->exit = lzma_exit;
		}
#endif
	} else if (encoding == wget_content_encoding_brotli) {
#ifdef WITH_BROTLIDEC
		if ((rc = brotli_init(&dc->brotli_strm)) == 0) {
			dc->decompress = brotli_decompress;
			dc->exit = brotli_exit;
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
	dc->sink = sink;
	dc->context = context;
	return dc;
}

void wget_decompress_close(wget_decompressor_t *dc)
{
	if (dc) {
		if (dc->exit)
			dc->exit(dc);
		xfree(dc);
	}
}

int wget_decompress(wget_decompressor_t *dc, char *src, size_t srclen)
{
	if (dc) {
		int rc = dc->decompress(dc, src, srclen);

		if (rc && dc->error_handler)
			dc->error_handler(dc->context, rc);
	}

	return 0;
}

void wget_decompress_set_error_handler(wget_decompressor_t *dc, wget_decompressor_error_handler_t error_handler)
{
	if (dc)
		dc->error_handler = error_handler;
}

void *wget_decompress_get_context(wget_decompressor_t *dc)
{
	return dc ? dc->context : NULL;
}

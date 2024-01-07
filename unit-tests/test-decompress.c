/* Test of condition variables in multithreaded situations.
	Copyright (C) 2008-2024 Free Software Foundation, Inc.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <wget.h>

#define uncompressed_body "x"

#define GZIP "\x1f\x8b\x08\x08\x48\x5d\x91\x5a\x00\x03\x78\x00\xab\x00\x00\x83\x16\xdc\x8c\x01\x00\x00\x00"	// gzip
#define DEFLATE "\x78\x9c\xab\x00\x00\x00\x79\x00\x79"	// deflate
#define BZIP2 "\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\x77\x4b\xb0\x14\x00\x00\x00\x00\x80\x00\x40\x20\x00\x21\x18\x46\x82\xee\x48\xa7\x0a\x12\x0e\xe9\x76\x02\x80"	// bzip2
#define XZ "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46\x02\x00\x21\x01\x16\x00\x00\x00\x74\x2f\xe5\xa3\x01\x00\x00\x78\x00\x00\x00\x00\x45\xae\xef\x83\xf8\xee\x16\x0a\x00\x01\x19\x01\xa5\x2c\x81\xcc\x1f\xb6\xf3\x7d\x01\x00\x00\x00\x00\x04\x59\x5a"	// xz
#define LZMA "\x5d\x00\x00\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x3c\x41\xfb\xff\xff\xff\xe0\x00\x00\x00"	// lzma
#define BR "\x21\x00\x00\x04\x78\x03"	// br
#define ZSTD "\x28\xb5\x2f\xfd\x24\x01\x09\x00\x00\x78\x23\x11\x04\x83"
#define LZIP "\x4c\x5a\x49\x50\x01\x0c\x00\x3c\x41\xfb\xff\xff\xff\xe0\x00\x00\x00\x83\x16\xdc\x8c\x01\x00\x00\x00\x00\x00\x00\x00\x25\x00\x00\x00\x00\x00\x00\x00"

#define countof(a) (sizeof(a)/sizeof(*(a)))

static int
	ok,
	failed;

static void check(int result, int line, const char *msg)
{
	if (result) {
		ok++;
	} else {
		failed++;
		wget_info_printf("L%d: %s\n", line, msg);
	}
}

#define CHECK(e) check(!!(e), __LINE__, #e)

static const struct compression_test_data {
	const char *body;
	size_t body_len;
	const char *type;
} test_data[] = {
#ifdef WITH_ZLIB
	{	GZIP, sizeof(GZIP) - 1, "gzip" },
	{	DEFLATE, sizeof(DEFLATE) - 1, "deflate" },
#endif
#ifdef WITH_BZIP2
	{	BZIP2, sizeof(BZIP2) - 1, "bzip2" },
#endif
#ifdef WITH_LZMA
	{	XZ, sizeof(XZ) - 1, "xz" },
	{	LZMA, sizeof(LZMA) - 1, "lzma" },
#endif
#ifdef WITH_BROTLIDEC
	{	BR, sizeof(BR) - 1, "br" },
#endif
#ifdef WITH_ZSTD
	{	ZSTD, sizeof(ZSTD) - 1, "zstd" },
#endif
#ifdef WITH_LZIP
	{	LZIP, sizeof(LZIP) - 1, "lzip" },
#endif
	{	uncompressed_body, sizeof(uncompressed_body) - 1, "identity" },
};


static int get_decompressed(void *userdata, const char *data, size_t length)
{
	wget_buffer_memcat((wget_buffer *)userdata, data, length);

	return 0;
}

#include "../libwget/private.h"

int main(WGET_GCC_UNUSED int argc, const char **argv)
{
	// if VALGRIND testing is enabled, we have to call ourselves with valgrind checking
	const char *valgrind = getenv("VALGRIND_TESTS");

	if (!valgrind || !*valgrind || !strcmp(valgrind, "0")) {
		// fallthrough
	}
	else if (!strcmp(valgrind, "1")) {
		char cmd[4096];

		wget_snprintf(cmd, sizeof(cmd), "VALGRIND_TESTS=\"\" valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes %s", argv[0]);
		return system(cmd) != 0;
	} else {
		char cmd[4096];

		wget_snprintf(cmd, sizeof(cmd), "VALGRIND_TESTS="" %s %s", valgrind, argv[0]);
		return system(cmd) != 0;
	}

	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stderr);
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);

	wget_buffer plain;
	wget_decompressor *dc = NULL;

	wget_buffer_init(&plain, NULL, sizeof(uncompressed_body) - 1);

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct compression_test_data *t = &test_data[it];

		wget_buffer_reset(&plain);

		wget_content_encoding content_encoding = wget_content_encoding_by_name(t->type);
		CHECK((dc = wget_decompress_open(content_encoding, get_decompressed, &plain)));

		if (dc) {
			wget_decompress(dc, t->body, t->body_len);
			wget_decompress_close(dc);

			wget_info_printf("%s %zu %zu\n", t->type, plain.length, sizeof(uncompressed_body) - 1);
			CHECK(plain.length == sizeof(uncompressed_body) - 1);
			CHECK(memcmp(plain.data, uncompressed_body, sizeof(uncompressed_body) - 1) == 0);
		}
	}

	wget_buffer_deinit(&plain);

	if (failed) {
		wget_info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	wget_info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}

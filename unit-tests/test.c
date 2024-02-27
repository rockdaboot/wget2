/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * test routines
 *
 * Changelog
 * 06.07.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#undef NDEBUG // always enable assertions in this test code
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <c-ctype.h>
#include <errno.h>
#include <inttypes.h>

#include <wget.h>
#include "../libwget/private.h"

#include "../src/wget_options.h"
#include "../src/wget_log.h"

static int
	ok,
	failed;

static void check(int result, int line, const char *msg)
{
	if (result) {
		ok++;
	} else {
		failed++;
		wget_error_printf_exit("L%d: %s\n", line, msg);
	}
}

#define CHECK(e) check(!!(e), __LINE__, #e)

static void test_mem(void)
{
	void *p;

#if __GNUC__ >= 7
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Walloc-zero"
#endif

	CHECK(!wget_memdup(NULL, 0));
	CHECK(!wget_memdup(NULL, 4));
	CHECK(p = wget_memdup("xxx", 0)); xfree(p);
	CHECK(p = wget_memdup("xxx", 4));
	CHECK(!memcmp(p, "xxx", 4)); xfree(p);

	CHECK(!wget_strdup(NULL));
	CHECK(p = wget_strdup("xxx"));
	CHECK(!strcmp(p, "xxx")); xfree(p);

	CHECK(!wget_strmemdup(NULL, 0));
	CHECK(p = wget_strmemdup("xxx", 1));
	CHECK(!memcmp(p, "x", 1)); xfree(p);
	CHECK(p = wget_strmemdup("xxx", 0));
	xfree(p);

	CHECK(wget_strmemcpy(NULL, 0, NULL, 0) == 0);
	CHECK(wget_strmemcpy(NULL, 5, NULL, 3) == 0);

	char buf[32] = "x";
	CHECK(wget_strmemcpy(buf, 0, "xxx", 0) == 0);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strmemcpy(buf, 0, "xxx", 1) == 0);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strmemcpy(buf, sizeof(buf), "xxx", 0) == 0);
	CHECK(!strcmp(buf, ""));
	CHECK(wget_strmemcpy(buf, 1, "xxx", 3) == 0);
	CHECK(!strcmp(buf, ""));
	CHECK(wget_strmemcpy(buf, 2, "xxx", 3) == 1);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strmemcpy(buf, 2, NULL, 3) == 0);
	CHECK(!strcmp(buf, ""));
	CHECK(wget_strmemcpy(buf, sizeof(buf), "xxx", 3) == 3);
	CHECK(!strcmp(buf, "xxx"));

#if __GNUC__ >= 7
#pragma GCC diagnostic pop
#endif

}

static void test_strlcpy(void)
{
	char buf[4] = "x";

	CHECK(wget_strlcpy(buf, NULL, 5) == 0);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strlcpy(NULL, "x", sizeof(buf)) == 1);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strlcpy(buf, "xx", sizeof(buf)) == 2);
	CHECK(!strcmp(buf, "xx"));
	CHECK(wget_strlcpy(buf, "xxxxx", sizeof(buf)) == 5);
	CHECK(!strcmp(buf, "xxx"));
}

static void test_strscpy(void)
{
	char buf[4] = "x";

	CHECK(wget_strscpy(NULL, "y", sizeof(buf)) == -1);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strscpy(buf, "y", 0) == -1);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strscpy(buf, NULL, 0) == -1);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strscpy(buf, NULL, 5) == 0);
	CHECK(!strcmp(buf, ""));
	CHECK(wget_strscpy(buf, "x", sizeof(buf)) == 1);
	CHECK(!strcmp(buf, "x"));
	CHECK(wget_strscpy(buf, "", sizeof(buf)) == 0);
	CHECK(!strcmp(buf, ""));
	CHECK(wget_strscpy(buf, "xx", sizeof(buf)) == 2);
	CHECK(!strcmp(buf, "xx"));
	CHECK(wget_strscpy(buf, "xxxxx", sizeof(buf)) == 3);
	CHECK(!strcmp(buf, "xxx"));
}

static void _test_buffer(wget_buffer *buf, const char *name)
{
	char test[256];
	int it;

	for (it = 0; it < (int)sizeof(test)-1; it++) {
		test[it] = 'a' + it % 26;
		test[it + 1] = 0;

		wget_buffer_strcpy(buf, test);
		wget_buffer_strcat(buf, test);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.1 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		wget_buffer_memcpy(buf, test, it + 1);
		wget_buffer_memcat(buf, test, it + 1);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.2 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		wget_buffer_printf(buf, "%s%s", test, test);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.3 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		wget_buffer_printf(buf, "%s", test);
		wget_buffer_printf_append(buf, "%s", test);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.4 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}
	}
}

static void test_buffer(void)
{
	char sbuf[16];
	wget_buffer buf, *bufp;

	// testing buffer on stack, using initial stack memory
	// without resizing

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_deinit(&buf);

	// testing buffer on stack, using initial stack memory
	// with resizing

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	_test_buffer(&buf, "Test 1");
	wget_buffer_deinit(&buf);

	// testing buffer on stack, using initial heap memory
	// without resizing

	wget_buffer_init(&buf, NULL, 16);
	wget_buffer_deinit(&buf);

	// testing buffer on stack, using initial heap memory
	// with resizing

	wget_buffer_init(&buf, NULL, 16);
	_test_buffer(&buf, "Test 2");
	wget_buffer_deinit(&buf);

	// testing buffer on stack, forcing internal allocation

	wget_buffer_init(&buf, sbuf, 0);
	wget_buffer_deinit(&buf);

	wget_buffer_init(&buf, sbuf, 0);
	_test_buffer(&buf, "Test 5");
	wget_buffer_deinit(&buf);

	// testing buffer on heap, using initial heap memory
	// without resizing

	bufp = wget_buffer_alloc(16);
	wget_buffer_free(&bufp);

	// testing buffer on heap, using initial heap memory
	// with resizing

	bufp = wget_buffer_alloc(16);
	_test_buffer(bufp, "Test 5");
	wget_buffer_free(&bufp);

	// check that appending works

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_strcpy(&buf, "A");
	wget_buffer_strcat(&buf, "B");
	wget_buffer_memcat(&buf, "C", 1);
	wget_buffer_memset_append(&buf, 'D', 1);
	wget_buffer_printf_append(&buf, "%s", "E");
	if (!strcmp(buf.data, "ABCDE"))
		ok++;
	else {
		failed++;
		info_printf("test_buffer.append: got %s (expected %s)\n", buf.data, "ABCDE");
	}
	wget_buffer_deinit(&buf);

	// test wget_buffer_trim()

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	for (int mid_ws = 0; mid_ws <= 2; mid_ws++) {
		char expected[16];
		snprintf(expected, sizeof(expected), "x%*.*sy", mid_ws, mid_ws, "");

		for (int lead_ws = 0; lead_ws <= 2; lead_ws++) {
			for (int trail_ws = 0; trail_ws <= 2; trail_ws++) {
				wget_buffer_printf(&buf, "%*.*sx%*.*sy%*.*s",
					lead_ws, lead_ws, "", mid_ws, mid_ws, "", trail_ws, trail_ws, "");
				wget_buffer_trim(&buf);
				if (!strcmp(buf.data, expected))
					ok++;
				else {
					failed++;
					info_printf("test_buffer_trim: got '%s' (expected '%s') (%d, %d, %d)\n", buf.data, expected, lead_ws, mid_ws, trail_ws);
				}
			}
		}
	}

	char expected[] = "";
	for (int ws = 0; ws <= 3; ws++) {
		wget_buffer_printf(&buf, "%*.*s", ws, ws, "");
		wget_buffer_trim(&buf);
		if (!strcmp(buf.data, expected))
			ok++;
		else {
			failed++;
			info_printf("test_buffer_trim: got '%s' (expected '%s') (%d)\n", buf.data, expected, ws);
		}
	}
	wget_buffer_deinit(&buf);

	// force reallocation
	assert(wget_buffer_init(&buf, sbuf, sizeof(sbuf)) == WGET_E_SUCCESS);
	wget_buffer_memset(&buf, 0, 4096);
	wget_buffer_free_data(&buf);
	assert(wget_buffer_ensure_capacity(&buf, 256) == WGET_E_SUCCESS);
	wget_buffer_memset(&buf, 0, 4096);
	assert((bufp = wget_buffer_alloc(0)) != NULL);
	wget_buffer_bufcpy(&buf, bufp);
	wget_buffer_strcpy(bufp, "moin");
	wget_buffer_bufcpy(&buf, bufp);
	wget_buffer_free(&bufp);
	wget_buffer_deinit(&buf);

	bufp = wget_buffer_alloc(16);
	assert(wget_buffer_strcpy(bufp, "moin") == 4);
	assert(wget_buffer_memset(bufp, 'A', 0) == 0);
	assert(*bufp->data == 0);
	wget_buffer_free(&bufp);
}

static void test_buffer_printf(void)
{
	char buf_static[32];
	wget_buffer buf;

	// testing buffer_printf() by comparing it with C standard function snprintf()

	static const char *zero_padded[] = { "", "0" };
	static const char *left_adjust[] = { "", "-" };
	static const long long number[] = { 0, 1LL, -1LL, 10LL, -10LL, 18446744073709551615ULL };
	static const char *modifier[] = { "", "h", "hh", "l", "ll", "z" }; // %L... won't work on OpenBSD5.0
	enum argtype { type_int, type_long, type_long_long, type_size_t };
	static const enum argtype modifier_type[] = { type_int, type_int, type_int, type_long, type_long_long, type_size_t };
	static const char *conversion[] = { "d", "i", "u", "o", "x", "X" };
	char fmt[32], result[64], string[32];
	size_t z, a, it, n, c, m;
	int width, precision, skip_left_string_padding;

	wget_buffer_init(&buf, buf_static, sizeof(buf_static));

	wget_buffer_printf(&buf, "%s://%s", "http", "host");
	if (strcmp("http://host", buf.data)) {
		failed++;
		info_printf("%s: Failed with format ('%%s://%%s','http','host'): '%s' != 'http://host'\n", __func__, buf.data);
		return;
	} else
		ok++;

	// sprintf on Solaris and Windows uses spaces instead of 0s for e.g. %03s padding
	// we skip those test when we detect such behavior
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wformat"
#endif
	snprintf(result, sizeof(result), "%02s", "1");
	skip_left_string_padding = (*result != ' ');
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
	#pragma GCC diagnostic pop
#endif

	for (z = 0; z < countof(zero_padded); z++) {
		for (a = 0; a < countof(left_adjust); a++) {
			for (width = -1; width < 12; width++) {
				for (precision = -1; precision < 12; precision++) {

					// testing %s stuff

					if (skip_left_string_padding && z == 1)
						goto integer_tests;

					if (width == -1) {
						if (precision == -1) {
							snprintf(fmt, sizeof(fmt), "abc%%%s%ssxyz", left_adjust[a], zero_padded[z]);
						} else {
							snprintf(fmt, sizeof(fmt), "abc%%%s%s.%dsxyz", left_adjust[a], zero_padded[z], precision);
						}
					} else {
						if (precision == -1) {
							snprintf(fmt, sizeof(fmt), "abc%%%s%s%dsxyz", left_adjust[a], zero_padded[z], width);
						} else {
							snprintf(fmt, sizeof(fmt), "abc%%%s%s%d.%dsxyz", left_adjust[a], zero_padded[z], width, precision);
						}
					}

					for (it = 0; it < sizeof(string); it++) {
						memset(string, 'a', it);
						string[it] = 0;

#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
						#pragma GCC diagnostic push
						#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
						snprintf(result, sizeof(result), fmt, string);
						wget_buffer_printf(&buf, fmt, string);
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
						#pragma GCC diagnostic pop
#endif
						if (strcmp(result, buf.data)) {
							failed++;
							info_printf("%s: Failed with format ('%s','%s'): '%s' != '%s'\n", __func__, fmt, string, buf.data, result);
							return;
						} else {
							// info_printf("%s: format ('%s','%s'): '%s' == '%s'\n", __func__, fmt, string, buf.data, result);
							ok++;
						}
					}

					if (width == -1) {
						if (precision == -1) {
							snprintf(fmt, sizeof(fmt), "%%%s%ss", left_adjust[a], zero_padded[z]);
						} else {
							snprintf(fmt, sizeof(fmt), "%%%s%s.*s", left_adjust[a], zero_padded[z]);
						}
					} else {
						if (precision == -1) {
							snprintf(fmt, sizeof(fmt), "%%%s%s*s", left_adjust[a], zero_padded[z]);
						} else {
							snprintf(fmt, sizeof(fmt), "%%%s%s*.*s", left_adjust[a], zero_padded[z]);
						}
					}

					for (it = 0; it < sizeof(string); it++) {
						memset(string, 'a', it);
						string[it] = 0;

#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
						#pragma GCC diagnostic push
						#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
						if (width == -1) {
							if (precision == -1) {
								snprintf(result, sizeof(result), fmt, string);
								wget_buffer_printf(&buf, fmt, string);
							} else {
								snprintf(result, sizeof(result), fmt, precision, string);
								wget_buffer_printf(&buf, fmt, precision, string);
							}
						} else {
							if (precision == -1) {
								snprintf(result, sizeof(result), fmt, width, string);
								wget_buffer_printf(&buf, fmt, width, string);
							} else {
								snprintf(result, sizeof(result), fmt, width, precision, string);
								wget_buffer_printf(&buf, fmt, width, precision, string);
							}
						}
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
						#pragma GCC diagnostic pop
#endif

						if (strcmp(result, buf.data)) {
							failed++;
							info_printf("%s: Failed with format ('%s','%s'): '%s' != '%s'\n", __func__, fmt, string, buf.data, result);
							return;
						} else {
							// info_printf("%s: format ('%s','%s'): '%s' == '%s'\n", __func__, fmt, string, buf.data, result);
							ok++;
						}
					}

					// testing integer stuff
integer_tests:
					for (m = 0; m < countof(modifier); m++) {
					for (c = 0; c < countof(conversion); c++) {
						if (width == -1) {
							if (precision == -1) {
								snprintf(fmt, sizeof(fmt), "%%%s%s%s%s", left_adjust[a], zero_padded[z], modifier[m], conversion[c]);
							} else {
								snprintf(fmt, sizeof(fmt), "%%%s%s.%d%s%s", left_adjust[a], zero_padded[z], precision, modifier[m], conversion[c]);
							}
						} else {
							if (precision == -1) {
								snprintf(fmt, sizeof(fmt), "%%%s%s%d%s%s", left_adjust[a], zero_padded[z], width, modifier[m], conversion[c]);
							} else {
								snprintf(fmt, sizeof(fmt), "%%%s%s%d.%d%s%s", left_adjust[a], zero_padded[z], width, precision, modifier[m], conversion[c]);
							}
						}

						for (n = 0; n < countof(number); n++) {
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
							#pragma GCC diagnostic push
							#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
							switch (modifier_type[m]) {
							case type_int:
								snprintf(result, sizeof(result), fmt, (int)number[n]);
								wget_buffer_printf(&buf, fmt, (int)number[n]);
								break;
							case type_long:
								snprintf(result, sizeof(result), fmt, (long)number[n]);
								wget_buffer_printf(&buf, fmt, (long)number[n]);
								break;
							case type_long_long:
								snprintf(result, sizeof(result), fmt, (long long)number[n]);
								wget_buffer_printf(&buf, fmt, (long long)number[n]);
								break;
							case type_size_t:
								snprintf(result, sizeof(result), fmt, (size_t)number[n]);
								wget_buffer_printf(&buf, fmt, (size_t)number[n]);
								break;
							default:
								abort();
							}
#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
							#pragma GCC diagnostic pop
#endif

							if (strcmp(result, buf.data)) {
								failed++;
								info_printf("%s: Failed with format ('%s','%lld'): '%s' != '%s'\n", __func__, fmt, number[n], buf.data, result);
//								return;
							} else {
								// info_printf("%s: format ('%s','%lld'): '%s' == '%s'\n", __func__, fmt, number[n], buf.data, result);
								ok++;
							}
						}
					}
					}
				}
			}
		}
	}

	wget_buffer_deinit(&buf);
}

static void test_iri_parse(void)
{
	const struct iri_test_data {
		const char
			*uri,
			*display;
		wget_iri_scheme
			scheme;
		const char
			*userinfo,
			*password,
			*host,
			*safe_uri;
		uint16_t
			port;
		const char
			*path,
			*query,
			*fragment;
	} test_data[] = {
		{ "1.2.3.4", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "1.2.3.4", "http://1.2.3.4", 80, NULL, NULL, NULL},
		{ "1.2.3.4:987", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "1.2.3.4", "http://1.2.3.4:987", 987, NULL, NULL, NULL},
		{ "[2a02:2e0:3fe:1001:302::]", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "2a02:2e0:3fe:1001:302::", "http://[2a02:2e0:3fe:1001:302::]", 80, NULL, NULL, NULL},
		{ "[2a02:2e0:3fe:1001:302::]:987", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "2a02:2e0:3fe:1001:302::", "http://[2a02:2e0:3fe:1001:302::]:987", 987, NULL, NULL, NULL},
		{ "//example.com/thepath", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http:////example.com/thepath", 80, "thepath", NULL, NULL},
		// { "///thepath", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, NULL, 0, "thepath", NULL, NULL},
		{ "example.com", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com", 80, NULL, NULL, NULL},
		{ "example.com:555", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com:555", 555, NULL, NULL, NULL},
		{ "http://example.com", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com", 80, NULL, NULL, NULL},
		{ "http://example.com:", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com:", 80, NULL, NULL, NULL},
		{ "http://example.com:/", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com:/", 80, "", NULL, NULL},
		{ "http://example.com:80/", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com:80/", 80, "", NULL, NULL},
		{ "https://example.com", NULL, WGET_IRI_SCHEME_HTTPS, NULL, NULL, "example.com", "https://example.com", 443, NULL, NULL, NULL},
		{ "https://example.com:443", NULL, WGET_IRI_SCHEME_HTTPS, NULL, NULL, "example.com", "https://example.com:443", 443, NULL, NULL, NULL},
		{ "https://example.com:444", NULL, WGET_IRI_SCHEME_HTTPS, NULL, NULL, "example.com", "https://example.com:444", 444, NULL, NULL, NULL},
		{ "http://example.com:80", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com:80", 80, NULL, NULL, NULL},
		{ "http://example.com:81", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com:81", 81, NULL, NULL, NULL},
		{ "http://example.com/index.html", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com/index.html", 80, "index.html", NULL, NULL},
		{ "http://example.com/index.html?query#frag", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com/index.html?query#frag", 80, "index.html", "query", "frag"},
		{ "http://example.com/index.html?query&param#frag", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com/index.html?query&param#frag", 80, "index.html", "query&param", "frag"},
		{ "http://example.com/index.html?query&par%26am%61x=1#frag", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com/index.html?query&par%26am%61x=1#frag", 80, "index.html", "query&par%26am%61x=1", "frag"},
		{ "http://example.com/index.html?#", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com/index.html?#", 80, "index.html", "", ""},
#if defined WITH_LIBIDN || defined WITH_LIBIDN2
		{ "碼標準萬國碼.com", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "xn--9cs565brid46mda086o.com", "http://碼標準萬國碼.com", 80, NULL, NULL, NULL},
#endif
		//		{ "ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm", NULL,"ftp",NULL,NULL,"cnn.example.com",0,NULL,"story=breaking_news@10.0.0.1/top_story.htm",NULL }
//		{ "ftp://cnn.example.com?story=breaking_news@10.0.0.1/top_story.htm", NULL, "ftp", NULL, NULL, "cnn.example.com", 0, NULL, "story=breaking_news@10.0.0.1/top_story.htm", NULL},
//		{ "site;sub:.html", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "site", 0, ";sub:.html", NULL, NULL},
//		{ "mailto:info@example.com", NULL, "mailto", "info", NULL, "example.com", 0, NULL, NULL, NULL},
		{ "http://example.com?query#frag", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com?query#frag", 80, NULL, "query", "frag"},
		{ "http://example.com#frag", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com#frag", 80, NULL, NULL, "frag"},
		{ "http://example.com?#", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com?#", 80, NULL, "", ""},
		{ "http://example+.com/pa+th?qu+ery#fr+ag", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example+.com", "http://example+.com/pa+th?qu+ery#fr+ag", 80, "pa+th", "qu ery", "fr+ag"},
		{ "http://example.com#frag?x", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com#frag?x", 80, NULL, NULL, "frag?x"},
		{ "http://user:pw@example.com", NULL, WGET_IRI_SCHEME_HTTP, "user", "pw", "example.com", "http://example.com", 80, NULL, NULL, NULL},
		{ "http://:@example.com", NULL, WGET_IRI_SCHEME_HTTP, "", "", "example.com", "http://example.com", 80, NULL, NULL, NULL},
		{ "http://user:@example.com", NULL, WGET_IRI_SCHEME_HTTP, "user", "", "example.com", "http://example.com", 80, NULL, NULL, NULL},
		{ "http://user@example.com", NULL, WGET_IRI_SCHEME_HTTP, "user", NULL, "example.com", "http://example.com", 80, NULL, NULL, NULL},
		{ "http://:pw@example.com", NULL, WGET_IRI_SCHEME_HTTP, "", "pw", "example.com", "http://example.com", 80, NULL, NULL, NULL},
		{ "http://user:pw@example@.com", NULL, WGET_IRI_SCHEME_HTTP, "user", "pw", "example@.com", "http://example@.com", 80, NULL, NULL, NULL},
		{ "http://user:pw@example.com/index.html?query&par%26am%61x=1#frag", NULL, WGET_IRI_SCHEME_HTTP, "user", "pw", "example.com", "http://example.com/index.html?query&par%26am%61x=1#frag", 80, "index.html", "query&par%26am%61x=1", "frag"},
		{ "http://example.com//path//file", NULL, WGET_IRI_SCHEME_HTTP, NULL, NULL, "example.com", "http://example.com//path//file", 80, "path/file", NULL, NULL},
	};
	unsigned it;

	for (it = 0; it < countof(test_data); it++) {
		const struct iri_test_data *t = &test_data[it];
		wget_iri *iri = wget_iri_parse(t->uri, "utf-8");

		if (wget_strcmp(iri->display, t->display)
			|| iri->scheme != t->scheme
			|| wget_strcmp(iri->userinfo, t->userinfo)
			|| wget_strcmp(iri->password, t->password)
			|| wget_strcmp(iri->host, t->host)
			|| wget_strcmp(iri->safe_uri, t->safe_uri)
			|| iri->port != t->port
			|| wget_strcmp(iri->path, t->path)
			|| wget_strcmp(iri->query, t->query)
			|| wget_strcmp(iri->fragment, t->fragment))
		{
			failed++;
			printf("IRI test #%u failed:\n", it + 1);
			printf(" [%s]\n", iri->uri);
			printf("  display %s (expected %s)\n", iri->display, t->display);
			printf("  scheme %s (expected %s)\n", wget_iri_scheme_get_name(iri->scheme), wget_iri_scheme_get_name(t->scheme));
			printf("  user %s (expected %s)\n", iri->userinfo, t->userinfo);
			printf("  password %s (expected %s)\n", iri->password, t->password);
			printf("  host %s (expected %s)\n", iri->host, t->host);
			printf("  safe uri %s (expected %s)\n", iri->safe_uri, t->safe_uri);
			printf("  port %hu (expected %hu)\n", iri->port, t->port);
			printf("  path %s (expected %s)\n", iri->path, t->path);
			printf("  query %s (expected %s)\n", iri->query, t->query);
			printf("  fragment %s (expected %s)\n", iri->fragment, t->fragment);
			printf("\n");
		} else {
			ok++;
		}

		wget_iri_free(&iri);
	}
}

/*
// testing with https://github.com/annevk/url/blob/master/urltests.txt
static void test_iri_parse_urltests(void)
{
	FILE *fp;
	char *buf = NULL;
	size_t bufsize;
	wget_iri *iri = NULL;
	int theline = 0;
	char f[8][128];

	if (!(fp = fopen("urltests.txt", "r"))) {
		failed++;
		info_printf("Failed to open urltests.txt");
		return;
	}

	while (wget_getline(&buf, &bufsize, fp) >= 0) {
		theline++;

		int n = sscanf(buf, "%127s %127s %127s %127s %127s %127s %127s %127s",
			f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]);

		if (n < 1)
			continue;

		if (*f[0] == '#')
			continue; // skip comments

		// parse URL
		if (!(iri = wget_iri_parse(f[0], "iso-8859-1"))) {
			info_printf("%s: Failed to parse '%s'\n", __func__, f[0]);
			continue;
		}

		// set defaults
		const char *scheme = "http";
		const char *host = "example.org";
		const char *port = NULL;
		const char *path = NULL;
		const char *query = NULL;
		const char *frag = NULL;
		const char *user = NULL;
		const char *pass = NULL;
		const char *display = NULL;

		for (int it = 1; it < n; it++) {
			const char *s = f[it];

			if (!strncmp(s, "s:", 2)) { // scheme
				scheme = s + 2;
			} else if (!strncmp(s, "h:", 2)) { // host
				host = s + 2;
			} else if (!strncmp(s, "port:", 5)) { // port
				port = s + 5;
			} else if (!strncmp(s, "p:", 2)) { // path
				if (s[2] == '/')
					path = s + 3;
				else
					path = s + 2;
			} else if (!strncmp(s, "q:", 2)) { // query
				if (s[2] == '?')
					query = s + 3;
				else
					query = s + 2;
			} else if (!strncmp(s, "f:", 2)) { // fragment
				if (s[2] == '#')
					frag = s + 3;
				else
					frag = s + 2;
			} else if (!strncmp(s, "u:", 2)) { // user
				user = s + 2;
			} else if (!strncmp(s, "pass:", 5)) { // pass
				pass = s + 5;
			} else
				info_printf("%s: Unknown tag '%s'\n", __func__, s);
		}

		if (wget_strcmp(iri->display, display)
			|| wget_strcmp(iri->scheme, scheme)
			|| wget_strcmp(iri->userinfo, user)
			|| wget_strcmp(iri->password, pass)
			|| wget_strcmp(iri->host, host)
			|| (wget_strcmp(iri->port, port) && iri->port && port && atoi(iri->port) != atoi(port))
			|| (wget_strcmp(iri->path, path) && iri->path && path && *path)
			|| wget_strcmp(iri->query, query)
			|| wget_strcmp(iri->fragment, frag))
		{
			failed++;
			printf("IRI urltests.txt line #%d failed:\n", theline + 1);
			printf(" [%s]\n", iri->uri);
			printf("  display %s (expected %s)\n", iri->display, display);
			printf("  scheme %s (expected %s)\n", iri->scheme, scheme);
			printf("  user %s (expected %s)\n", iri->userinfo, user);
			printf("  pass %s (expected %s)\n", iri->password, pass);
			printf("  host %s (expected %s)\n", iri->host, host);
			printf("  port %s (expected %s)\n", iri->port, port);
			printf("  path %s (expected %s)\n", iri->path, path);
			printf("  query %s (expected %s)\n", iri->query, query);
			printf("  fragment %s (expected %s)\n", iri->fragment, frag);
			printf("\n");
		} else {
			ok++;
		}

		wget_iri_free(&iri);
	}

	fclose(fp);
}
*/

static void test_iri_relative_to_absolute(void)
{
	static const struct iri_test_data {
		const char
			*base,
			*relative,
			*result;
	} test_data[] = {
#define H1 "http://x.tld"
		{ H1, "", H1"/" },
		{ H1, ".", H1"/" },
		{ H1, "./", H1"/" },
		{ H1, "..", H1"/" },
		{ H1, "../", H1"/" },
		{ H1, "foo", H1"/foo" },
		{ H1, "foo%3A", H1"/foo%3A" }, // escaped colon
		{ H1, "foo/bar", H1"/foo/bar" },
		{ H1, "foo///bar", H1"/foo/bar" },
		{ H1, "foo/.", H1"/foo/" },
		{ H1, "foo/./", H1"/foo/" },
		{ H1, "foo./", H1"/foo./" },
		{ H1, "foo/../bar", H1"/bar" },
		{ H1, "foo/../bar/", H1"/bar/" },
		{ H1, "foo/bar/..", H1"/foo/" },
		{ H1, "foo/bar/../x", H1"/foo/x" },
		{ H1, "foo/bar/../x/", H1"/foo/x/" },
		{ H1, "foo/..", H1"/" },
		{ H1, "foo/../..", H1"/" },
		{ H1, "foo/../../..", H1"/" },
		{ H1, "foo/../../bar/../../baz", H1"/baz" },
		{ H1, "a/b/../../c", H1"/c" },
		{ H1, "./a/../b", H1"/b" },
		{ H1, "/", H1"/" },
		{ H1, "/.", H1"/" },
		{ H1, "/./", H1"/" },
		{ H1, "/..", H1"/" },
		{ H1, "/../", H1"/" },
		{ H1, "/foo", H1"/foo" },
		{ H1, "/foo/bar", H1"/foo/bar" },
		{ H1, "/foo///bar", H1"/foo/bar" },
		{ H1, "/foo/.", H1"/foo/" },
		{ H1, "/foo/./", H1"/foo/" },
		{ H1, "/foo./", H1"/foo./" },
		{ H1, "/foo/../bar", H1"/bar" },
		{ H1, "/foo/../bar/", H1"/bar/" },
		{ H1, "/foo/bar/..", H1"/foo/" },
		{ H1, "/foo/bar/../x", H1"/foo/x" },
		{ H1, "/foo/bar/../x/", H1"/foo/x/" },
		{ H1, "/foo/..", H1"/" },
		{ H1, "/foo/../..", H1"/" },
		{ H1, "/foo/../../..", H1"/" },
		{ H1, "/foo/../../bar/../../baz", H1"/baz" },
		{ H1, "/a/b/../../c", H1"/c" },
		{ H1, "/./a/../b", H1"/b" },
		{ H1, ".x", H1"/.x" },
		{ H1, "..x", H1"/..x" },
		{ H1, "foo/.x", H1"/foo/.x" },
		{ H1, "foo/bar/.x", H1"/foo/bar/.x" },
		{ H1, "foo/..x", H1"/foo/..x" },
		{ H1, "foo/bar/..x", H1"/foo/bar/..x" },
		{ H1, "/x.php?y=ftp://example.com/&z=1_2", H1"/x.php?y=ftp://example.com/&z=1_2" },
		{ H1, "//x.y.com/", "http://x.y.com/" },
		{ H1, "http://x.y.com/", "http://x.y.com/" },
//		{ H1, "site;sub:.html", H1"/site;sub:.html" },
#undef H1
#define H1 "http://x.tld/"
		{ H1, "", H1"" },
		{ H1, ".", H1"" },
		{ H1, "./", H1"" },
		{ H1, "..", H1"" },
		{ H1, "../", H1"" },
		{ H1, "foo", H1"foo" },
		{ H1, "foo/bar", H1"foo/bar" },
		{ H1, "foo///bar", H1"foo/bar" },
		{ H1, "foo/.", H1"foo/" },
		{ H1, "foo/./", H1"foo/" },
		{ H1, "foo./", H1"foo./" },
		{ H1, "foo/../bar", H1"bar" },
		{ H1, "foo/../bar/", H1"bar/" },
		{ H1, "foo/bar/..", H1"foo/" },
		{ H1, "foo/bar/../x", H1"foo/x" },
		{ H1, "foo/bar/../x/", H1"foo/x/" },
		{ H1, "foo/..", H1"" },
		{ H1, "foo/../..", H1"" },
		{ H1, "foo/../../..", H1"" },
		{ H1, "foo/../../bar/../../baz", H1"baz" },
		{ H1, "a/b/../../c", H1"c" },
		{ H1, "./a/../b", H1"b" },
		{ H1, "/", H1"" },
		{ H1, "/.", H1"" },
		{ H1, "/./", H1"" },
		{ H1, "/..", H1"" },
		{ H1, "/../", H1"" },
		{ H1, "/foo", H1"foo" },
		{ H1, "/foo/bar", H1"foo/bar" },
		{ H1, "/foo///bar", H1"foo/bar" },
		{ H1, "/foo/.", H1"foo/" },
		{ H1, "/foo/./", H1"foo/" },
		{ H1, "/foo./", H1"foo./" },
		{ H1, "/foo/../bar", H1"bar" },
		{ H1, "/foo/../bar/", H1"bar/" },
		{ H1, "/foo/bar/..", H1"foo/" },
		{ H1, "/foo/bar/../x", H1"foo/x" },
		{ H1, "/foo/bar/../x/", H1"foo/x/" },
		{ H1, "/foo/..", H1"" },
		{ H1, "/foo/../..", H1"" },
		{ H1, "/foo/../../..", H1"" },
		{ H1, "/foo/../../bar/../../baz", H1"baz" },
		{ H1, "/a/b/../../c", H1"c" },
		{ H1, "/./a/../b", H1"b" },
		{ H1, ".x", H1".x" },
		{ H1, "..x", H1"..x" },
		{ H1, "foo/.x", H1"foo/.x" },
		{ H1, "foo/bar/.x", H1"foo/bar/.x" },
		{ H1, "foo/..x", H1"foo/..x" },
		{ H1, "foo/bar/..x", H1"foo/bar/..x" },
		{ H1, "/x.php?y=ftp://example.com/&z=1_2", H1"x.php?y=ftp://example.com/&z=1_2" },
		{ H1, "//x.y.com/", "http://x.y.com/" },
		{ H1, "http://x.y.com/", "http://x.y.com/" },
#undef H1
#define H1 "http://x.tld/file"
#define R1 "http://x.tld/"
		{ H1, "", R1"" },
		{ H1, ".", R1"" },
		{ H1, "./", R1"" },
		{ H1, "..", R1"" },
		{ H1, "../", R1"" },
		{ H1, "foo", R1"foo" },
		{ H1, "foo/bar", R1"foo/bar" },
		{ H1, "foo///bar", R1"foo/bar" },
		{ H1, "foo/.", R1"foo/" },
		{ H1, "foo/./", R1"foo/" },
		{ H1, "foo./", R1"foo./" },
		{ H1, "foo/../bar", R1"bar" },
		{ H1, "foo/../bar/", R1"bar/" },
		{ H1, "foo/bar/..", R1"foo/" },
		{ H1, "foo/bar/../x", R1"foo/x" },
		{ H1, "foo/bar/../x/", R1"foo/x/" },
		{ H1, "foo/..", R1"" },
		{ H1, "foo/../..", R1"" },
		{ H1, "foo/../../..", R1"" },
		{ H1, "foo/../../bar/../../baz", R1"baz" },
		{ H1, "a/b/../../c", R1"c" },
		{ H1, "./a/../b", R1"b" },
		{ H1, "/", R1"" },
		{ H1, "/.", R1"" },
		{ H1, "/./", R1"" },
		{ H1, "/..", R1"" },
		{ H1, "/../", R1"" },
		{ H1, "/foo", R1"foo" },
		{ H1, "/foo/bar", R1"foo/bar" },
		{ H1, "/foo///bar", R1"foo/bar" },
		{ H1, "/foo/.", R1"foo/" },
		{ H1, "/foo/./", R1"foo/" },
		{ H1, "/foo./", R1"foo./" },
		{ H1, "/foo/../bar", R1"bar" },
		{ H1, "/foo/../bar/", R1"bar/" },
		{ H1, "/foo/bar/..", R1"foo/" },
		{ H1, "/foo/bar/../x", R1"foo/x" },
		{ H1, "/foo/bar/../x/", R1"foo/x/" },
		{ H1, "/foo/..", R1"" },
		{ H1, "/foo/../..", R1"" },
		{ H1, "/foo/../../..", R1"" },
		{ H1, "/foo/../../bar/../../baz", R1"baz" },
		{ H1, "/a/b/../../c", R1"c" },
		{ H1, "/./a/../b", R1"b" },
		{ H1, ".x", R1".x" },
		{ H1, "..x", R1"..x" },
		{ H1, "foo/.x", R1"foo/.x" },
		{ H1, "foo/bar/.x", R1"foo/bar/.x" },
		{ H1, "foo/..x", R1"foo/..x" },
		{ H1, "foo/bar/..x", R1"foo/bar/..x" },
		{ H1, "/x.php?y=ftp://example.com/&z=1_2", R1"x.php?y=ftp://example.com/&z=1_2" },
		{ H1, "//x.y.com/", "http://x.y.com/" },
		{ H1, "http://x.y.com/", "http://x.y.com/" },
#undef H1
#undef R1
#define H1 "http://x.tld/dir/"
#define R1 "http://x.tld/"
		{ H1, "", H1"" },
		{ H1, ".", H1"" },
		{ H1, "./", H1"" },
		{ H1, "..", R1"" },
		{ H1, "../", R1"" },
		{ H1, "foo", H1"foo" },
		{ H1, "foo/bar", H1"foo/bar" },
		{ H1, "foo///bar", H1"foo/bar" },
		{ H1, "foo/.", H1"foo/" },
		{ H1, "foo/./", H1"foo/" },
		{ H1, "foo./", H1"foo./" },
		{ H1, "foo/../bar", H1"bar" },
		{ H1, "foo/../bar/", H1"bar/" },
		{ H1, "foo/bar/..", H1"foo/" },
		{ H1, "foo/bar/../x", H1"foo/x" },
		{ H1, "foo/bar/../x/", H1"foo/x/" },
		{ H1, "foo/..", H1"" },
		{ H1, "foo/../..", R1"" },
		{ H1, "foo/../../..", R1"" },
		{ H1, "foo/../../bar/../../baz", R1"baz" },
		{ H1, "a/b/../../c", H1"c" },
		{ H1, "./a/../b", H1"b" },
		{ H1, "/", R1"" },
		{ H1, "/.", R1"" },
		{ H1, "/./", R1"" },
		{ H1, "/..", R1"" },
		{ H1, "/../", R1"" },
		{ H1, "/foo", R1"foo" },
		{ H1, "/foo/bar", R1"foo/bar" },
		{ H1, "/foo///bar", R1"foo/bar" },
		{ H1, "/foo/.", R1"foo/" },
		{ H1, "/foo/./", R1"foo/" },
		{ H1, "/foo./", R1"foo./" },
		{ H1, "/foo/../bar", R1"bar" },
		{ H1, "/foo/../bar/", R1"bar/" },
		{ H1, "/foo/bar/..", R1"foo/" },
		{ H1, "/foo/bar/../x", R1"foo/x" },
		{ H1, "/foo/bar/../x/", R1"foo/x/" },
		{ H1, "/foo/..", R1"" },
		{ H1, "/foo/../..", R1"" },
		{ H1, "/foo/../../..", R1"" },
		{ H1, "/foo/../../bar/../../baz", R1"baz" },
		{ H1, "/a/b/../../c", R1"c" },
		{ H1, "/./a/../b", R1"b" },
		{ H1, ".x", H1".x" },
		{ H1, "..x", H1"..x" },
		{ H1, "foo/.x", H1"foo/.x" },
		{ H1, "foo/bar/.x", H1"foo/bar/.x" },
		{ H1, "foo/..x", H1"foo/..x" },
		{ H1, "foo/bar/..x", H1"foo/bar/..x" },
		{ H1, "/x.php?y=ftp://example.com/&z=1_2", R1"x.php?y=ftp://example.com/&z=1_2" },
		{ H1, "//x.y.com/", "http://x.y.com/" },
		{ H1, "http://x.y.com/", "http://x.y.com/" }
#undef H1
#undef R1
	};
	unsigned it;
	char uri_buf_static[32]; // use a size that forces allocation in some cases
	wget_buffer uri_buf;
	wget_iri *base;

	wget_buffer_init(&uri_buf, uri_buf_static, sizeof(uri_buf_static));

	for (it = 0; it < countof(test_data); it++) {
		const struct iri_test_data *t = &test_data[it];

		base = wget_iri_parse(t->base, "utf-8");
		wget_iri_relative_to_abs(base, t->relative, (size_t) -1, &uri_buf);

		if (!strcmp(uri_buf.data, t->result))
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: %s+%s -> %s (expected %s)\n", it, t->base, t->relative, uri_buf.data, t->result);
		}

		wget_iri_free(&base);
	}

	wget_buffer_deinit(&uri_buf);
}

static void test_iri_compare(void)
{
	static const struct iri_test_data {
		const char
			*url1,
			*url2;
		int
			result;
	} test_data[] = {
		{ "http://abc.com", "http://abc.com/", -1}, // different, some web servers redirect ... to .../ due to normalization issues
		{ "http://abc.com", "http://abc.com:", 0},
		{ "http://abc.com", "http://abc.com:/", -1},
		{ "http://abc.com", "http://abc.com:80/", -1},
		{ "http://abc.com", "http://abc.com:80//", -1},
		// { "http://äöü.com", "http://ÄÖÜ.com:80//", 0},
		{ "http://abc.com:80/~smith/home.html", "http://abc.com/~smith/home.html", 0},
		{ "http://abc.com:80/~smith/home.html", "http://ABC.com/~smith/home.html", 0},
		{ "http://abc.com:80/~smith/home.html", "http://ABC.com/%7Esmith/home.html", 0},
		{ "http://abc.com:80/~smith/home.html", "http://ABC.com/%7esmith/home.html", 0},
		{ "http://ABC.com/%7esmith/home.html", "http://ABC.com/%7Esmith/home.html", 0},
		{ "http://ABC.com/%7esmith/home.html", "http://ACB.com/%7Esmith/home.html", -1}
	};
	unsigned it;
	int n;

	for (it = 0; it < countof(test_data); it++) {
		const struct iri_test_data *t = &test_data[it];
		wget_iri *iri1 = wget_iri_parse(t->url1, "utf-8");
		wget_iri *iri2 = wget_iri_parse(t->url2, "utf-8");

		n = wget_iri_compare(iri1, iri2);
		if (n < -1) n = -1;
		else if (n > 1) n = 1;

		if (n == t->result)
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: compare(%s,%s) -> %d (expected %d)\n", it, t->url1, t->url2, n, t->result);
			printf("  display %s / %s\n", iri1->display, iri2->display);
			printf("  scheme %s / %s\n",  wget_iri_scheme_get_name(iri1->scheme),  wget_iri_scheme_get_name(iri2->scheme));
			printf("  user %s / %s\n", iri1->userinfo, iri2->userinfo);
			printf("  host %s / %s\n", iri1->host, iri2->host);
			printf("  port %hu / %hu\n", iri1->port, iri2->port);
			printf("  path %s / %s\n", iri1->path, iri2->path);
			printf("  query %s / %s\n", iri1->query, iri2->query);
			printf("  fragment %s / %s\n", iri1->fragment, iri2->fragment);
			printf("\n");
		}

		wget_iri_free(&iri2);
		wget_iri_free(&iri1);
	}
}

/*
static void _css_dump_charset(WGET_GCC_UNUSED void *user_ctx, const char *encoding, size_t len)
{
	debug_printf("URI content encoding = '%.*s'\n", (int)len, encoding);
}

static void _css_dump_uri(WGET_GCC_UNUSED void *user_ctx, const char *url, size_t len, WGET_GCC_UNUSED size_t pos)
{
	debug_printf("*** %zu '%.*s'\n", len, (int)len, url);
}
*/

static void test_parser(void)
{
	DIR *dirp;
	int xml = 0, html = 0, css = 0;

	// test the XML / HTML parser, you should start the test with valgrind
	// to detect memory faults
	if ((dirp = opendir(SRCDIR "/files")) != NULL) {
		const char *ext;
		struct dirent *dp;

		while ((dp = readdir(dirp)) != NULL) {
			if (*dp->d_name == '.') continue;
			if ((ext = strrchr(dp->d_name, '.'))) {
				char fname[4096];
				wget_snprintf(fname, sizeof(fname), "%s/files/%s", SRCDIR, dp->d_name);
				if (!wget_strcasecmp_ascii(ext, ".xml")) {
					info_printf("parsing %s\n", fname);
					wget_xml_parse_file(fname, NULL, NULL, 0);
					xml++;
				}
/*				else if (!wget_strcasecmp_ascii(ext, ".html")) {
					info_printf("parsing %s\n", fname);
					wget_html_parse_file(fname, NULL, NULL, 0);
					html++;
				}
				else if (!wget_strcasecmp_ascii(ext, ".css")) {
					info_printf("parsing %s\n", fname);
					wget_css_parse_file(fname, _css_dump_uri, _css_dump_charset, NULL);
					css++;
				} */
			}
		}
		closedir(dirp);
	}

	info_printf("%d XML, %d HTML and %d CSS files parsed\n", xml, html, css);
}

static void test_cookies(void)
{
#ifdef WITH_LIBPSL
	#define _PSL_RESULT_FAIL -1
#else
	#define _PSL_RESULT_FAIL 0
#endif
	static const struct test_data {
		const char
			*uri,
			*set_cookie,
			*expected_set_cookie;
		int
			result,
			psl_result;
	} test_data[] = {
		{	// allowed cookie
			"www.example.com",
			"ID=65=abcd; expires=Tuesday, 07-May-2013 07:48:53 GMT; path=/; domain=.example.com; HttpOnly",
			"ID=65=abcd; expires=Tue, 07 May 2013 07:48:53 GMT; path=/; domain=.example.com; HttpOnly",
			0, 0
		},
		{	// allowed cookie ANSI C's asctime format
			"www.example.com",
			"ID=65=abcd; expires=Tue May 07 07:48:53 2013; path=/; domain=.example.com",
			"ID=65=abcd; expires=Tue, 07 May 2013 07:48:53 GMT; path=/; domain=.example.com",
			0, 0
		},
		{	// allowed cookie without path
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; domain=.example.com",
			"ID=65=abcd; expires=Tue, 07 May 2013 07:48:53 GMT; path=/; domain=.example.com",
			0, 0
		},
		{	// allowed cookie without domain
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; path=/",
			"ID=65=abcd; expires=Tue, 07 May 2013 07:48:53 GMT; path=/; domain=www.example.com",
			0, 0
		},
		{	// non-standard expires (found in reality)
			"www.example.com",
			"ID=65=abcd; expires=1 Mar 2027 09:23:12 GMT; path=/",
			"ID=65=abcd; expires=Mon, 01 Mar 2027 09:23:12 GMT; path=/; domain=www.example.com",
			0, 0
		},
		{	// allowed cookie without domain, path and expires
			"www.example.com",
			"ID=65=abcd",
			"ID=65=abcd; path=/; domain=www.example.com",
			0, 0
		},
		{	// illegal cookie (.com against .org)
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; path=/; domain=.example.org",
			NULL,
			-1, 0
		},
//#ifdef WITH_LIBPSL
		{	// supercookie, accepted by normalization (rule 'com') but not by wget_cookie_check_psl())
			"www.example.com",
			"ID=65=abcd; expires=Mon, 29-Feb-2016 07:48:54 GMT; path=/; domain=.com; HttpOnly; Secure",
			"ID=65=abcd; expires=Mon, 29 Feb 2016 07:48:54 GMT; path=/; domain=.com; HttpOnly; Secure",
			0, _PSL_RESULT_FAIL
		},
		{	// supercookie, accepted by normalization  (rule 'sa.gov.au') but not by wget_cookie_check_psl())
			"www.sa.gov.au",
			"ID=65=abcd; expires=Tue, 29-Feb-2000 07:48:55 GMT; path=/; domain=.sa.gov.au",
			"ID=65=abcd; expires=Tue, 29 Feb 2000 07:48:55 GMT; path=/; domain=.sa.gov.au",
			0, _PSL_RESULT_FAIL
		},
//#endif
		{	// exception rule '!educ.ar', accepted by normalization
			"www.educ.ar",
			"ID=65=abcd; path=/; domain=.educ.ar",
			"ID=65=abcd; path=/; domain=.educ.ar",
			0, 0
		},

		// Examples from draft-ietf-httpbis-cookie-prefixes-00
		{	// Rejected due to missing 'secure' flag
			"http://example.com",
			"__Secure-SID=12345; Domain=example.com",
			NULL,
			-1, 0
		},
		{	// Rejected due to missing 'secure' flag
			"https://example.com",
			"__Secure-SID=12345; Domain=example.com",
			NULL,
			-1, 0
		},
		{	// Rejected due to set from a insecure origin
			"http://example.com",
			"__Secure-SID=12345; Secure; Domain=example.com",
			NULL,
			-1, 0
		},
		{	// Accepted
			"https://example.com",
			"__Secure-SID=12345; Secure; Domain=example.com",
			"__Secure-SID=12345; path=/; domain=example.com; Secure",
			0, 0
		},
		{	// Rejected (missing 'secure', path not /)
			"https://example.com",
			"__Host-SID=12345",
			NULL,
			-1, _PSL_RESULT_FAIL
		},
		{	// Rejected (path not /)
			"https://example.com",
			"__Host-SID=12345; Secure",
			NULL,
			-1, _PSL_RESULT_FAIL
		},
		{	// Rejected (missing secure, domain given, path not /)
			"https://example.com",
			"__Host-SID=12345; Domain=example.com",
			NULL,
			-1, 0
		},
		{	// Rejected (missing secure, domain given)
			"https://example.com",
			"__Host-SID=12345; Domain=example.com; Path=/",
			NULL,
			-1, 0
		},
		{	// Rejected (domain given)
			"https://example.com",
			"__Host-SID=12345; Secure; Domain=example.com; Path=/",
			NULL,
			-1, 0
		},
		{	// Rejected (insecure origin)
			"http://example.com",
			"__Host-SID=12345; Secure; Path=/",
			NULL,
			-1, _PSL_RESULT_FAIL
		},
		{	// Accepted
			"https://example.com",
			"__Host-SID=12345; Secure; Path=/",
			NULL,
			-1, _PSL_RESULT_FAIL
		},

	};
	wget_cookie *cookie = NULL;
	wget_cookie_db *cookies;
	unsigned it;
	int result, result_psl;

	cookies = wget_cookie_db_init(NULL);

	if (wget_cookie_db_load_psl(cookies, SRCDIR "/files/public_suffix_list.dat") == -1) {
#ifdef WITH_LIBPSL
			failed++;
			info_printf("Failed to load %s (errno=%d)\n", SRCDIR "/files/public_suffix_list.dat", errno);
#endif
			goto out;
	}

	for (it = 0; it < countof(test_data); it++) {
		char *header, *set_cookie;
		const struct test_data *t = &test_data[it];
		wget_iri *iri = wget_iri_parse(t->uri, "utf-8");

		wget_http_parse_setcookie(t->set_cookie, &cookie);

		if ((result = wget_cookie_normalize(iri, cookie)) != t->result) {
			failed++;
			info_printf("Failed [%u]: normalize_cookie(%s) -> %d (expected %d)\n", it, t->set_cookie, result, t->result);
			goto next;
		} else if (result == 0) {
			if ((result_psl = wget_cookie_check_psl(cookies, cookie)) != t->psl_result) {
				failed++;
				info_printf("Failed [%u]: PSL check(%s) -> %d (expected %d)\n", it, t->set_cookie, result_psl, t->psl_result);
				goto next;
			}
		} else
			goto next;

/*		if (cookie->expires) {
			char thedate[32];

			wget_http_print_date(cookie->expires, thedate, sizeof(thedate));
			if (strcmp(thedate, t->expires)) {
				failed++;
				info_printf("Failed [%u]: expires mismatch: '%s' != '%s' (time_t %lld)\n", it, thedate, t->expires, (long long)cookie.expires);
				goto next;
			}
		}
*/

		set_cookie = wget_cookie_to_setcookie(cookie);

		if (wget_strcmp(set_cookie, t->expected_set_cookie)) {
			failed++;

			info_printf("Failed [%u]: cookie (%s) differs:\n", it, t->set_cookie);
			info_printf("-%s\n", t->expected_set_cookie);
			info_printf("+%s\n", set_cookie);

			xfree(set_cookie);
			goto next;
		}

		xfree(set_cookie);

		wget_cookie_store_cookie(cookies, cookie); // takes ownership of cookie
		cookie = NULL;

		// just check for memory issues
		header = wget_cookie_create_request_header(cookies, iri);
		xfree(header);

		ok++;

next:
		wget_cookie_free(&cookie);
		wget_iri_free(&iri);
	}

out:
	wget_cookie_db_free(&cookies);
}

static void test_hsts(void)
{
	static const struct hsts_db_data {
		const char *
			host;
		uint16_t
			port;
		const char *
			hsts_params;
	} hsts_db_data[] = {
		{ "www.example.com", 443, "max-age=14400; includeSubDomains" },
		{ "www.example2.com", 443, "max-age=14400" },
		{ "www.example2.com", 443, "max-age=0" }, // this removes the previous entry
	};
	static const struct hsts_data {
		const char *
			host;
		uint16_t
			port;
		int
			result;
	} hsts_data[] = {
		{ "www.example.com", 443, 1 }, // exact match
		{ "ftp.example.com", 443, 0 },
		{ "example.com", 443, 0 },
		{ "sub.www.example.com", 443, 1 }, // subdomain
		{ "sub1.sub2.www.example.com", 443, 1 }, // subdomain
		{ "www.example2.com", 443, 0 }, // entry should have been removed due to maxage=0
		{ "www.example.com", 80, 1 }, // default port
		{ "www.example.com", 8080, 0 }, // wrong port
	};
	wget_hsts_db *hsts_db = wget_hsts_db_init(NULL, NULL);
	int64_t maxage;
	bool include_subdomains;
	int n;

	// fill HSTS database with values
	for (unsigned it = 0; it < countof(hsts_db_data); it++) {
		const struct hsts_db_data *t = &hsts_db_data[it];
		wget_http_parse_strict_transport_security(t->hsts_params, &maxage, &include_subdomains);
		wget_hsts_db_add(hsts_db, t->host, t->port, maxage, include_subdomains);
	}

	// check HSTS database with values
	for (unsigned it = 0; it < countof(hsts_data); it++) {
		const struct hsts_data *t = &hsts_data[it];

		n = wget_hsts_host_match(hsts_db, t->host, t->port);

		if (n == t->result)
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: wget_hsts_host_match(%s,%d) -> %d (expected %d)\n", it, t->host, t->port, n, t->result);
		}
	}

	wget_hsts_db_free(&hsts_db);
}

/* need to create pin-sha256 values for Public-Key-Pins: HTTP header */
/*
static const char *_sha256_base64(const void *src)
{
	char digest[wget_hash_get_len(WGET_DIGTYPE_SHA256)];
//	static char base64[wget_base64_get_encoded_length(sizeof(digest)) + 1];
	static char base64[128];
	size_t len = strlen(src);

	if (wget_hash_fast(WGET_DIGTYPE_SHA256, src, len, digest))
		return "";

	wget_base64_encode(base64, digest, sizeof(digest));
	base64[sizeof(base64)] = 0;

	return base64;
}
*/

#define HPKP_PUBKEY_1 "pubkey1"
#define HPKP_PUBKEY_2 "pubkey2"
#define HPKP_PUBKEY_3 "pubkey3"
#define HPKP_PIN_1 "RxmgXsIrtjMhR8zanWqTw+QUWqeJj4fCvmOyoKbw5lg="
#define HPKP_PIN_2 "Ic8LNwKypu+EXTi/ld8yp6P7lEH1jDVNIly8P/ykeWo="
#define HPKP_PIN_3 "/szJ2BMcM2l9Ypapui03ZcpqNJUvwsfi2uMKHZBTuaw="
#define HPKP_PIN_SIZE 32

static void test_hpkp(void)
{
	struct hpkp_db_data {
		const char *
			host;
		uint16_t
			port;
		const char *
			hpkp_params;
	} hpkp_db_data[] = {
		{ "www.example.com", 443, "max-age=14400; includeSubDomains; "\
		  "pin-sha256=\"" HPKP_PIN_1 "\"; pin-sha256=\"" HPKP_PIN_2 "\"; pin-sha256=\"" HPKP_PIN_3 "\"" },
		{ "www.example2.com", 443, "max-age=14400; "\
		  "pin-sha256=\"" HPKP_PIN_1 "\"; pin-sha256=\"" HPKP_PIN_2 "\"" },
		{ "www.example2.com", 443, "max-age=0" }, // this removes the previous entry due to max-age=0
		{ "www.example3.com", 443, "max-age=14400; "\
		  "pin-sha256=\"" HPKP_PIN_1 "\"; pin-sha256=\"" HPKP_PIN_2 "\"" },
		{ "www.example3.com", 443, "max-age=14400" }, // this removes the previous entry, due to no PINs
	};
	struct hpkp_db_params {
		int64_t
			maxage;
		bool
			include_subdomains;
		int
			n_pins;
		unsigned int
			pins_mask;
	} hpkp_db_params[] = {
		{ 14400, 1, 3, 7 },
		{ 14400, 0, 2, 3 },
		{ 0,     0, 0, 0 },
		{ 14400, 0, 2, 3 },
		{ 14400, 0, 0, 0 }
	};
	const char *hpkp_pins[] = { HPKP_PIN_1, HPKP_PIN_2, HPKP_PIN_3 };
	char hpkp_pins_binary[countof(hpkp_pins)][HPKP_PIN_SIZE + 1];

	for (unsigned it = 0; it < countof(hpkp_pins); it++)
		wget_base64_decode(hpkp_pins_binary[it], hpkp_pins[it], strlen(hpkp_pins[it]));

	static const struct hpkp_data {
		const char *
			host;
		const char *
			pubkey;
		int
			result;
	} hpkp_data[] = {
		{ "www.example.com", HPKP_PUBKEY_1, 1 }, // host match, pubkey #1
		{ "www.example.com", HPKP_PUBKEY_2, 1 }, // host match, pubkey #2
		{ "www.example.com", HPKP_PUBKEY_3, 1 }, // host match, pubkey #3
		{ "www.example.com", "nomatch", -2 }, // host match, pubkey does not match
		{ "ftp.example.com", HPKP_PUBKEY_1, 0 }, // no match at all
		{ "example.com", HPKP_PUBKEY_1, 0 }, // super domain, no match at all
		{ "sub.www.example.com", HPKP_PUBKEY_1, 1 }, // single subdomain
		{ "sub1.sub2.www.example.com", HPKP_PUBKEY_1, 1 }, // double subdomain
		{ "www.example2.com", HPKP_PUBKEY_1, 0 }, // entry should have been removed due to max-age=0
		{ "www.example3.com", HPKP_PUBKEY_1, 0 }, // entry should have been removed due to no PINs
	};
	wget_hpkp_db *hpkp_db = wget_hpkp_db_init(NULL, NULL);
	int n;

	/* generate values for pin-sha256 */
	// printf("#define HPKP_PIN_1 \"%s\"\n", _sha256_base64(HPKP_PUBKEY_1));
	// printf("#define HPKP_PIN_2 \"%s\"\n", _sha256_base64(HPKP_PUBKEY_2));
	// printf("#define HPKP_PIN_3 \"%s\"\n", _sha256_base64(HPKP_PUBKEY_3));

	// fill HPKP database with values
	for (unsigned it = 0; it < countof(hpkp_db_data); it++) {
		const struct hpkp_db_data *t = &hpkp_db_data[it];
		wget_hpkp *hpkp = wget_hpkp_new();

		wget_hpkp_set_host(hpkp, t->host);
		wget_http_parse_public_key_pins(t->hpkp_params, hpkp);

		// Check the database entry before adding
		{
			int n_pins, k;
			const char *pin_types[countof(hpkp_pins)], *pins[countof(hpkp_pins)];
			size_t pin_sizes[countof(hpkp_pins)];
			const void *pins_binary[countof(hpkp_pins)];

			// Check host, maxage, include_subdomains and n_pins
			if (strcmp(wget_hpkp_get_host(hpkp), hpkp_db_data[it].host) != 0) {
				failed++;
				info_printf("Failed [%u]: wget_hpkp_get_host(hpkp) -> %s (expected %s)\n", it,
					wget_hpkp_get_host(hpkp), hpkp_db_data[it].host);
			} else {
				ok++;
			}
			if (wget_hpkp_get_maxage(hpkp) != hpkp_db_params[it].maxage) {
				failed++;
				info_printf("Failed [%u]: wget_hpkp_get_maxage(hpkp) -> %llu (expected %llu)\n", it,
					(unsigned long long) wget_hpkp_get_maxage(hpkp),
					(unsigned long long) hpkp_db_params[it].maxage);
			} else {
				ok++;
			}
			if (wget_hpkp_get_include_subdomains(hpkp) != hpkp_db_params[it].include_subdomains) {
				failed++;
				info_printf("Failed [%u]: wget_hpkp_get_include_subdomains(hpkp) -> %d (expected %d)\n", it,
						wget_hpkp_get_include_subdomains(hpkp), hpkp_db_params[it].include_subdomains);
			} else {
				ok++;
			}
			n_pins = wget_hpkp_get_n_pins(hpkp);
			if (n_pins != hpkp_db_params[it].n_pins) {
				failed++;
				info_printf("Failed [%u]: wget_hpkp_get_n_pins(hpkp) -> %d (expected %d)\n", it,
						n_pins, hpkp_db_params[it].n_pins);
			} else {
				ok++;
			}

			// Check the pins
			wget_hpkp_get_pins_b64(hpkp, pin_types, pins);
			wget_hpkp_get_pins(hpkp, pin_types, pin_sizes, pins_binary);
			for (unsigned j = 0; j < countof(hpkp_pins); j++) {
				if (! ((1 << j) & hpkp_db_params[it].pins_mask))
					continue;
				for (k = 0; k < n_pins; k++) {
					if (strcmp(pin_types[k], "sha256") != 0)
						continue;
					if (pin_sizes[k] != HPKP_PIN_SIZE)
						continue;
					if (memcmp(pins_binary[k], hpkp_pins_binary[j], HPKP_PIN_SIZE) != 0)
						continue;
					if (strcmp(pins[k], hpkp_pins[j]) == 0)
						break;
				}
				if (k == n_pins) {
					failed++;
					info_printf("Failed [%u]: Pin %s not found in hpkp entry\n", it, hpkp_pins[j]);
				} else {
					ok++;
				}
			}
		}
		wget_hpkp_db_add(hpkp_db, &hpkp);
	}

	// check HPKP database with values
	for (unsigned it = 0; it < countof(hpkp_data); it++) {
		const struct hpkp_data *t = &hpkp_data[it];

		n = wget_hpkp_db_check_pubkey(hpkp_db, t->host, t->pubkey, strlen(t->pubkey));

		if (n == t->result)
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: wget_hpkp_db_check_pubkey(%s,%s) -> %d (expected %d)\n", it, t->host, t->pubkey, n, t->result);
		}
	}

	wget_hpkp_db_free(&hpkp_db);
}

static void test_parse_challenge(void)
{
	static const struct test_data {
		const char *
			input;
		const char *
			scheme[3];
	} test_data[] = {
		{	// simplebasic
			"Basic realm=\"foo\"",
			{ "Basic", NULL }
		},
		{	// simplebasicucase
			"BASIC REALM=\"foo\"",
			{ "Basic", NULL }
		},
		{	// simplebasicucase
			"Basic , realm=\"foo\"",
			{ "Basic", NULL }
		},
		{	//
			"Basic realm=\"test realm\"",
			{ "Basic", NULL }
		},
		{	//
			"Basic realm=\"test-äöÜ\"",
			{ "Basic", NULL }
		},
		{	//
			"Basic realm=\"basic\", Newauth realm=\"newauth\"",
			{ "Basic", "Newauth", NULL }
		},
	};

	wget_vector *challenges;
	wget_http_challenge *challenge;

	// Testcases found here http://greenbytes.de/tech/tc/httpauth/
	challenges = wget_vector_create(2, NULL);
	wget_vector_set_destructor(challenges, (wget_vector_destructor *) wget_http_free_challenge);

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];

		wget_http_parse_challenges(t->input, challenges);
		for (unsigned nchal = 0; nchal < countof(test_data[0].scheme) && t->scheme[nchal]; nchal++) {
			challenge = wget_vector_get(challenges, nchal);

			if (!t->scheme[nchal]) {
				if (challenge) {
					failed++;
					info_printf("Failed [%u]: wget_http_parse_challenges(%s) found %d challenges (expected %u)\n", it, t->input, wget_vector_size(challenges), nchal);
				}
				break;
			}

			if (!challenge) {
				failed++;
				info_printf("Failed [%u]: wget_http_parse_challenges(%s) did not find enough challenges\n", it, t->input);
				break;
			}

			if (!wget_strcasecmp_ascii(challenge->auth_scheme, t->scheme[nchal])) {
				ok++;
			} else {
				failed++;
				info_printf("Failed [%u]: wget_http_parse_challenges(%s) -> '%s' (expected '%s')\n", it, t->input, challenge->auth_scheme, t->scheme[nchal]);
			}
		}

		wget_vector_clear(challenges);
	}

	wget_http_free_challenges(&challenges);
}

static void test_utils(void)
{
	int it;
	unsigned char src[1];
	char dst1[3], dst2[3];

	for (int ndst = 1; ndst <= 3; ndst++) {
		for (it = 0; it <= 255; it++) {
			src[0] = (unsigned char) it;
			wget_memtohex(src, 1, dst1, ndst);
			wget_snprintf(dst2, ndst, "%02x", src[0]);
			if (strcmp(dst1, dst2)) {
				info_printf("buffer_to_hex failed: '%s' instead of '%s' (ndst=%d)\n", dst1, dst2, ndst);
				failed++;
				break;
			}
		}

		if (it >= 256)
			ok++;
		else
			failed++;
	}
}

static void test_strcasecmp_ascii(void)
{
	static const struct test_data {
		const char *
			s1;
		const char *
			s2;
		int
			result;
	} test_data[] = {
		{ NULL, NULL, 0 },
		{ NULL, "x", -1 },
		{ "x", NULL, 1 },
		{ "Abc", "abc", 0 },
		{ "abc", "abc", 0 },
		{ "abc", "ab", 'c' },
		{ "ab", "abc", -'c' },
		{ "abc", "", 'a' },
		{ "", "abc", -'a' },
	};
	static const struct test_data2 {
		const char *
			s1;
		const char *
			s2;
		size_t
			n;
		int
			result;
	} test_data2[] = {
		{ NULL, NULL, 1, 0 },
		{ NULL, "x", 1, -1 },
		{ "x", NULL, 1, 1 },
		{ "Abc", "abc", 2, 0 },
		{ "abc", "abc", 3, 0 },
		{ "abc", "ab", 2, 0 },
		{ "abc", "ab", 3, 'c' },
		{ "ab", "abc", 2, 0 },
		{ "ab", "abc", 3, -'c' },
		{ "abc", "", 1, 'a' },
		{ "", "abc", 1, -'a' },
		{ "", "abc", 0, 0 },
	};

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];

		int n = wget_strcasecmp_ascii(t->s1, t->s2);

		if (n == t->result)
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: wget_strcasecmp_ascii(%s,%s) -> %d (expected %d)\n", it, t->s1, t->s2, n, t->result);
		}
	}

	for (unsigned it = 0; it < countof(test_data2); it++) {
		const struct test_data2 *t = &test_data2[it];

		int n = wget_strncasecmp_ascii(t->s1, t->s2, t->n);

		if (n == t->result)
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: wget_strncasecmp_ascii(%s,%s,%zu) -> %d (expected %d)\n", it, t->s1, t->s2, t->n, n, t->result);
		}
	}

	for (unsigned char it = 0; it < 26; it++) {
		char s1[8], s2[8];

		s1[0] = 'a' + it; s1[1] = 0;
		s2[0] = 'A' + it; s2[1] = 0;

		if (wget_strcasecmp_ascii(s1, s2) == 0)
			ok++;
		else {
			failed++;
			info_printf("Failed: wget_strcasecmp_ascii(%s,%s) != 0\n", s1, s2);
		}

		if (wget_strncasecmp_ascii(s1, s2, 1) == 0)
			ok++;
		else {
			failed++;
			info_printf("Failed: wget_strncasecmp_ascii(%s,%s) != 0\n", s1, s2);
		}
	}
}

static void test_hashing(void)
{
	static const struct test_data {
		const char *
			text;
		const char *
			result;
		int
			algo;
	} test_data[] = {
		{ "moin", "06a998cdd13c50b7875775d4e7e9fa74", WGET_DIGTYPE_MD5 },
		{ "moin", "ba3cffcc93a92e08f82c33c55d887666fdf364ae", WGET_DIGTYPE_SHA1 },
		{ "moin", "2500d0ed4d0ea1b3ea9f7f57a5f16c2fba8ad15d05d3c057d42f9796f1250169", WGET_DIGTYPE_SHA256 },
		{ "moin", "e3ab1c142d6136fd938c810d13deaf47ccdb176687fab916611302ceb6a89787f45fdda2df544fec4f5a9a2a40916f316fcdf57bc27b5b757b7598da24c7c4c4", WGET_DIGTYPE_SHA512 },
	};
	unsigned char digest[64];
	char digest_hex[sizeof(digest) * 2 + 1];
	int rc;

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];

		if ((rc = wget_hash_fast(t->algo, t->text, strlen(t->text), digest)) == 0) {
			int len = wget_hash_get_len(t->algo);

			wget_memtohex(digest, len, digest_hex, len * 2 + 1);

			if (!strcmp(digest_hex, t->result))
				ok++;
			else {
				failed++;
				info_printf("Failed [%u]: wget_hash_fast(%s,%d) -> %s (expected %s)\n", it, t->text, t->algo, digest_hex, t->result);
			}

			// now let's test init/hash/deinit
			wget_hash_hd *handle;

			if ((rc = wget_hash_init(&handle, t->algo)) != 0) {
				failed++;
				info_printf("Failed [%u]: wget_hash_init(%d) -> %d (expected 0)\n", it, t->algo, rc);
				continue;
			}
			if ((rc = wget_hash(handle, t->text, strlen(t->text))) != 0) {
				failed++;
				info_printf("Failed [%u]: wget_hash(%s) -> %d (expected 0)\n", it, t->text, rc);
				continue;
			}
			if ((rc = wget_hash_deinit(&handle, digest)) != 0) {
				failed++;
				info_printf("Failed [%u]: wget_hash_deinit() -> %d (expected 0)\n", it, rc);
				continue;
			}

			wget_memtohex(digest, len, digest_hex, len * 2 + 1);

			if (!strcmp(digest_hex, t->result))
				ok++;
			else {
				failed++;
				info_printf("Failed [%u]: wget_hash_init/hash/deinit(%s,%d) -> %s (expected %s)\n", it, t->text, t->algo, digest_hex, t->result);
			}

		} else if (rc != WGET_E_UNSUPPORTED) {
			failed++;
			info_printf("Failed [%u]: wget_hash_fast(%s,%d) failed with %d\n", it, t->text, t->algo, rc);
		} else {
			// Skipping if not supported in libwget. Depends on the configurged crypto backend.
			info_printf("Skip hashing [%u]\n", it);
		}
	}
}

struct ENTRY {
	const char
		*txt;
};

static int compare_txt(struct ENTRY *a1, struct ENTRY *a2)
{
	return wget_strcasecmp_ascii(a1->txt, a2->txt);
}

static void test_vector(void)
{
	struct ENTRY
		*tmp,
		txt_sorted[5] = { {""}, {"four"}, {"one"}, {"three"}, {"two"} },
		*txt[countof(txt_sorted)];
	wget_vector
		*v = wget_vector_create(2, (wget_vector_compare_fn *) compare_txt);
	unsigned
		it;
	int
		n;

	// copy
	for (it = 0; it < countof(txt); it++)
		txt[it] = &txt_sorted[it];

	// shuffle txt
	for (it = 0; it < countof(txt); it++) {
		n = rand() % countof(txt);
		tmp = txt[n];
		txt[n] = txt[it];
		txt[it] = tmp;
	}

	for (it = 0; it < countof(txt); it++) {
		wget_vector_insert_sorted(v, txt[it]);
	}

	for (it = 0; it < countof(txt); it++) {
		struct ENTRY *e = wget_vector_get(v, it);
		if (!strcmp(e->txt,txt_sorted[it].txt))
			ok++;
		else
			failed++;
	}

	wget_vector_clear_nofree(v);
	wget_vector_free(&v);
}

// this hash function generates collisions and reduces the map to a simple list.
// O(1) insertion, but O(n) search and removal
static wget_stringmap_hash_fn hash_txt;
static unsigned int hash_txt(WGET_GCC_UNUSED const char *key)
{
	return 0;
}

static void test_stringmap(void)
{
	wget_stringmap *m;
	wget_stringmap_iterator *iter;
	char *key, *value, *val, *skey;
	char keybuf[1024];
	int run, it;

	// the initial size of 16 forces the internal reshashing function to be called twice

	m = wget_stringmap_create(16);

	for (run = 0; run < 2; run++) {
		if (run) {
			wget_stringmap_clear(m);
			wget_stringmap_sethashfunc(m, hash_txt);
		}

		for (it = 0; it < 26; it++) {
			key = wget_aprintf("http://www.example.com/subdir/%d.html", it);
			value = wget_aprintf("%d.html", it);
			if (wget_stringmap_put(m, key, value)) {
				failed++;
				info_printf("stringmap_put(%s) returns unexpected old value\n", key);
			} else ok++;
		}

		if ((it = wget_stringmap_size(m)) != 26) {
			failed++;
			info_printf("stringmap_size() returned %d (expected %d)\n", it, 26);
		} else ok++;

		iter = wget_stringmap_iterator_alloc(m);
		for (it = 0; (skey = wget_stringmap_iterator_next(iter, (void **) &val)); it++) {
			int x = atoi(skey + 30), y = atoi(val);

			if (!(c_isdigit(*val) && x >= 0 && x == y)) {
				failed++;
				info_printf("key/value don't match (%s | %s)\n", skey, val);
			} else ok++;
		}
		wget_stringmap_iterator_free(&iter);

		if (it != wget_stringmap_size(m)) {
			failed++;
			info_printf("stringmap iterator just found %d items (expected %d)\n", it, wget_stringmap_size(m));
		} else ok++;

		// now, look up every single entry
		for (it = 0; it < 26; it++) {
			wget_snprintf(keybuf, sizeof(keybuf), "http://www.example.com/subdir/%d.html", it);
			value = strrchr(keybuf, '/') + 1;
			if (!wget_stringmap_get(m, keybuf, &val)) {
				failed++;
				info_printf("stringmap_get(%s) didn't find entry\n", keybuf);
			} else if (strcmp(val, value)) {
				failed++;
				info_printf("stringmap_get(%s) found '%s' (expected '%s')\n", keybuf, val, value);
			} else ok++;
		}

		wget_stringmap_clear(m);

		if ((it = wget_stringmap_size(m)) != 0) {
			failed++;
			info_printf("stringmap_size() returned %d (expected 0)\n", it);
		} else ok++;

		for (it = 0; it < 26; it++) {
			key = wget_aprintf("http://www.example.com/subdir/%d.html", it);
			value = wget_aprintf("%d.html", it);
			if (wget_stringmap_put(m, key, value)) {
				failed++;
				info_printf("stringmap_put(%s) returns unexpected old value\n", key);
			} else ok++;
		}

		if ((it = wget_stringmap_size(m)) != 26) {
			failed++;
			info_printf("stringmap_size() returned %d (expected %d)\n", it, 26);
		} else ok++;

		// now, remove every single entry
		for (it = 0; it < 26; it++) {
			wget_snprintf(keybuf, sizeof(keybuf), "http://www.example.com/subdir/%d.html", it);
			wget_stringmap_remove(m, keybuf);
		}

		if ((it = wget_stringmap_size(m)) != 0) {
			failed++;
			info_printf("stringmap_size() returned %d (expected 0)\n", it);
		} else ok++;

		for (it = 0; it < 26; it++) {
			key = wget_aprintf("http://www.example.com/subdir/%d.html", it);
			value = wget_aprintf("%d.html", it);
			if (wget_stringmap_put(m, key, value)) {
				failed++;
				info_printf("stringmap_put(%s) returns unexpected old value\n", key);
			} else ok++;
		}

		if ((it = wget_stringmap_size(m)) != 26) {
			failed++;
			info_printf("stringmap_size() returned %d (expected %d)\n", it, 26);
		} else ok++;
	}

	// testing alloc/free in stringmap/hashmap
	wget_stringmap_clear(m);
	wget_stringmap_put(m, wget_strdup("thekey"), NULL) ? failed++ : ok++;
	wget_stringmap_put(m, wget_strdup("thekey"), NULL) ? ok++ : failed++;
	wget_stringmap_put(m, wget_strdup("thekey"), wget_strdup("thevalue")) ? ok++ : failed++;
	wget_stringmap_put(m, wget_strdup("thekey"), wget_strdup("thevalue")) ? ok++ : failed++;
	wget_stringmap_put(m, wget_strdup("thekey"), NULL) ? ok++ : failed++;

	// testing key/value identity alloc/free in stringmap/hashmap
	wget_stringmap_clear(m);
	wget_stringmap_put(m, wget_strdup("thekey"), NULL) ? failed++ : ok++;
	wget_stringmap_put(m, wget_strdup("thekey"), NULL) ? ok++ : failed++;
	wget_stringmap_put(m, wget_strdup("thekey"), wget_strdup("thevalue")) ? ok++ : failed++;
	wget_stringmap_put(m, wget_strdup("thekey"), NULL) ? ok++ : failed++;

	wget_stringmap_free(&m);

	wget_http_challenge *challenge = wget_calloc(1, sizeof(wget_http_challenge));
	wget_http_parse_challenge("Basic realm=\"test realm\"", challenge);
	wget_http_free_challenge(challenge);

	wget_vector *challenges;
	challenges = wget_vector_create(2, NULL);
	wget_vector_set_destructor(challenges, (wget_vector_destructor *) wget_http_free_challenge);
	challenge = wget_calloc(1, sizeof(wget_http_challenge));
	wget_http_parse_challenge("Basic realm=\"test realm\"", challenge);
	wget_vector_add(challenges, challenge);
	wget_vector_free(&challenges);

	char *response_text = wget_strdup(
"HTTP/1.1 401 Authorization Required\r\n"\
"Date: Sun, 23 Dec 2012 21:03:45 GMT\r\n"\
"Server: Apache/2.2.22 (Debian)\r\n"\
"WWW-Authenticate: Digest realm=\"therealm\", nonce=\"Ip6MaovRBAA=c4af733c51270698260f5d357724c2cbce20fa3d\", algorithm=MD5, domain=\"/prot_digest_md5\", qop=\"auth\"\r\n"\
"Vary: Accept-Encoding\r\n"\
"Content-Length: 476\r\n"\
"Keep-Alive: timeout=5, max=99\r\n"\
"Connection: Keep-Alive\r\n"\
"Content-Type: text/html; charset=iso-8859-1\r\n\r\n");

	wget_iri *iri = wget_iri_parse("http://localhost/prot_digest_md5/", NULL);
	wget_http_request *req = wget_http_create_request(iri, "GET");
	wget_http_response *resp = wget_http_parse_response_header(response_text);
	wget_http_add_credentials(req, wget_vector_get(resp->challenges, 0), "tim", "123", 0);
//	for (it=0;it<vec_size(req->lines);it++) {
//		info_printf("%s\n", (char *)vec_get(req->lines, it));
//	}
	wget_http_free_response(&resp);
	wget_http_free_request(&req);
	wget_iri_free(&iri);
	xfree(response_text);

// Authorization: Digest username="tim", realm="therealm", nonce="Ip6MaovRBAA=c4af733c51270698260f5d357724c2cbce20fa3d", uri="/prot_digest_md5/", response="a99e2012d507a73dd46eb044d3f4641c", qop=auth, nc=00000001, cnonce="3d20faa1"

}

static void test_striconv(void)
{
	const char *utf8 = "abcßüäö";
	char *utf16be = NULL, *utf16le = NULL, *result = NULL;
	size_t n;

	// convert utf-8 to utf-16be
	if (wget_memiconv("utf-8", utf8, strlen(utf8), "UTF-16BE", &utf16be, &n) ||
		wget_memiconv("UTF-16BE", utf16be, n, "UTF-16LE", &utf16le, &n) ||
		wget_memiconv("UTF-16LE", utf16le, n, "UTF-8", &result, &n) ||
		strcmp(utf8, result))
	{
		info_printf("Character conversion of '%s' failed (got '%s')\n", utf8, result);
		failed++;
	} else {
		ok++;
	}

	xfree(result);
	xfree(utf16le);
	xfree(utf16be);
}

static void test_bitmap(void)
{
	wget_bitmap *b;

	assert(wget_bitmap_init(&b, 1000) == WGET_E_SUCCESS);
	assert(b != NULL);

	assert(wget_bitmap_get(b, 0) == 0);
	assert(wget_bitmap_get(b, 999) == 0);
	assert(wget_bitmap_get(b, 1000) == 0);

	wget_bitmap_set(b, 1);
	wget_bitmap_set(b, 999);
	wget_bitmap_set(b, 1000); // should be a no-op
	assert(wget_bitmap_get(b, 0) == 0);
	assert(wget_bitmap_get(b, 1) == 1);
	assert(wget_bitmap_get(b, 999) == 1);
	assert(wget_bitmap_get(b, 1000) == 0);

	wget_bitmap_clear(b, 1);
	wget_bitmap_clear(b, 999);
	wget_bitmap_clear(b, 1000); // should be a no-op
	assert(wget_bitmap_get(b, 0) == 0);
	assert(wget_bitmap_get(b, 1) == 0);
	assert(wget_bitmap_get(b, 999) == 0);

	wget_bitmap_free(&b);
}

static void test_bar(void)
{
	wget_bar *bar;

	/* testing unexpected values */
	for (int i = -2; i <= 2; i++) {
		bar = wget_bar_init(NULL, i);
		wget_bar_free(&bar);
	}

	/* testing unexpected values */
	bar = NULL;
	for (int i = -2; i <= 2; i++) {
		bar = wget_bar_init(bar, i);
		wget_bar_free(&bar);
	}

	bar = wget_bar_init(NULL, 1);
	wget_bar_free(&bar);

	bar = wget_bar_init(NULL, 1);
	wget_bar_free(&bar);
}

static void test_netrc(void)
{
	struct test_entry {
		const char
			*host, *login, *password;
	};
	static const struct test_data {
		const char *
			text;
		int
			entries;
		struct test_entry
			entry[5];
	} test_data[] = {
		{
			"machine localhost\n"
			"login theuser\n"
			"password thepw",
			1,
			{
				{ "localhost", "theuser", "thepw" }
			}
		},
		{
			"machine localhost\n"
			"login theuser\n"
			"password thepw\n",
			1,
			{
				{ "localhost", "theuser", "thepw" }
			}
		},
		{
			"machine localhost\n"
			"login theuser password thepw\n",
			1,
			{
				{ "localhost", "theuser", "thepw" }
			}
		},
		{
			"machine localhost login theuser password thepw",
			1,
			{
				{ "localhost", "theuser", "thepw" }
			}
		},
		{
			"machine localhost login theuser password thepw\n"
			"machine localhost2 login theuser2 password thepw2\n"
			"machine abc login 111 password 222\n",
			3,
			{
				{ "localhost", "theuser", "thepw" },
				{ "localhost2", "theuser2", "thepw2" },
				{ "abc", "111", "222" }
			}
		},
		{ "machine m\nlogin u\npassword a\\b", 1,       {{ "m", "u", "ab" }} },
		{ "machine m\nlogin u\npassword a\\\\b", 1,     {{ "m", "u", "a\\b" }} },
		{ "machine m\nlogin u\npassword \"a\\\\b\"", 1, {{ "m", "u", "a\\b" }} },
		{ "machine m\nlogin u\npassword \"a\\\"b\"", 1, {{ "m", "u", "a\"b" }} },
		{ "machine m\nlogin u\npassword a\"b", 1,       {{ "m", "u", "a\"b" }} },
		{ "machine m\nlogin u\npassword a\\\\\\\\b", 1, {{ "m", "u", "a\\\\b" }} },
		{ "machine m\nlogin u\npassword a\\\\", 1,      {{ "m", "u", "a\\" }} },
		{ "machine m\nlogin u\npassword \"a\\\\\"", 1,  {{ "m", "u", "a\\" }} },
		{ "machine m\nlogin u\npassword a\\", 1,        {{ "m", "u", "a" }} },
		{ "machine m\nlogin u\npassword \"a b\"", 1,    {{ "m", "u", "a b" }} },
		{ "machine m\nlogin u\npassword a b", 1,        {{ "m", "u", "a" }} },
		{ "machine m\nlogin u\npassword a\\ b", 1,        {{ "m", "u", "a b" }} },
	};
	FILE *fp;
	wget_netrc_db *netrc_db;
	wget_netrc *netrc;
	int rc;

	mkdir(".test", 0700);

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];

		if ((fp = fopen(".test/.netrc", "w"))) {
			fwrite(t->text, 1, strlen(t->text), fp);
			fclose(fp);
		} else {
			info_printf("Failed to w-open .test/.netrc\n");
			failed++;
			continue;
		}

		netrc_db = wget_netrc_db_init(NULL);

		if ((rc = wget_netrc_db_load(netrc_db, ".test/.netrc")) != t->entries) {
			info_printf("[%u] Failed to read %d .netrc entries, found %d\n", it, t->entries, rc);
			failed++;
		} else {
			for (unsigned it2 = 0; it2 < countof(t->entry); it2++) {
				const struct test_entry *e = &t->entry[it2];
				if (!e->host) break;

				if (!(netrc = wget_netrc_get(netrc_db, e->host))) {
					info_printf("[%u] Failed to get host '%s' from netrc_db\n", it, e->host);
					failed++;
				}
				else if (strcmp(netrc->login, e->login)) {
					info_printf("[%u] Login mismatch in netrc_db: expected '%s', got '%s'\n", it, e->login, netrc->login);
					failed++;
				}
				else if (strcmp(netrc->password, e->password)) {
					info_printf("[%u] Password mismatch in netrc_db: expected '%s', got '%s'\n", it, e->password, netrc->password);
					failed++;
				} else
					ok++;
			}
		}


		wget_netrc_db_free(&netrc_db);
	}

	unlink(".test/.netrc");
	rmdir(".test");
}

static void test_robots(void)
{
	static const struct test_data {
		const char *
			name;
		const char *
			input;
		const char *
			path[3];
		const char *
			sitemap[3];
	} test_data[] = {
		{
			"Allow all + sitemap",
			"User-agent: *\n"
			"Disallow: # allow all\n"
			"Sitemap: http://www.example.com/sitemap.xml",
			{ NULL },
			{ "http://www.example.com/sitemap.xml", NULL }
		},
		{
			"Allow wget2, bar but deny foo /cgi-bin and deny all /",
			"User-agent: foo\n"
			"User-agent: wget2\n"
			"Disallow: /cgi-bin/\n"
			"Sitemap: \n"
			"User-agent: bar\n"
			"User-agent: wget2\n"
			"Disallow: \n"
			"User-agent: *\n"
			"Disallow: /",
			{ NULL },
			{ NULL }
		},
		{
			"Deny all /cgi-bin",
			"User-agent: *\n"
			"Disallow: /cgi-bin/ # comment\n",
			{ "/cgi-bin/", NULL },
			{ NULL }
		},
		{
			"Deny all /",
			"User-agent: *\n"
			"Disallow: /\n",
			{ "/", NULL },
			{ NULL }
		},
		{
			"Deny wget2 /cgi/bin",
			"User-agent: wget2\n"
			"Disallow: /cgi-bin/\n",
			{ "/cgi-bin/", NULL },
			{ NULL }
		},
		{
			"Deny wget2 /",
			"User-agent: wget2\n"
			"Disallow: /\n",
			{ "/", NULL },
			{ NULL }
		},
		{
			"Deny all but allow wget2",
			"User-agent: *\n"
			"Disallow: /\n"
			"User-agent: wget2\n"
			"Disallow: \n",
			{ NULL },
			{ NULL }
		},
		{
			"Deny all and deny wget2 /cgi-bin/",
			"User-agent: *\n"
			"Disallow: /\n"
			"User-agent: wget2\n"
			"Disallow: /cgi-bin/",
			{ "/cgi-bin/", NULL },
			{ NULL }
		},
		{
			"Allow all",
			"User-agent: *\n"
			"Disallow: \n",
			{ NULL },
			{ NULL }
		},
		{
			"Deny all /cgi-bin + sitemap",
			// with 1 sitemap
			"User-agent: *\n"
			"Disallow: /cgi-bin/\n"
			"Sitemap: http://www.example.com/sitemap.xml",
			{ "/cgi-bin/", NULL },
			{ "http://www.example.com/sitemap.xml", NULL }
		},
		{
			"Allow all but deny wget2 /cgi-bin, /tmp + 2 sitemaps",
			" User-agent : *\n"
			" Disallow : \n"
			" User-agent : wget2\n"
			" User-agent : foo\n"
			" Disallow : /cgi-bin/#This is a comment\n"
			" Sitemap : http://www.example1.com/sitemap.xml\n"
			" Sitemap : \n"
			" Sitemap : http://www.example2.com/sitemap.xml#Another comment\n"
			" User-agent : bar\n"
			" User-agent : wget2\n"
			" Disallow : /tmp/",
			{ "/cgi-bin/", "/tmp/", NULL },
			{ "http://www.example1.com/sitemap.xml", "http://www.example2.com/sitemap.xml", NULL }
		},
		{
			"Deny all /cgi-bin + 2 sitemaps",
			"User-agent: *\n"
			"Disallow: /cgi-bin/\n"
			"Sitemap: http://www.example1.com/sitemap.xml\n"
			"Sitemap: http://www.example2.com/sitemap.xml",
			{ "/cgi-bin/", NULL },
			{ "http://www.example1.com/sitemap.xml", "http://www.example2.com/sitemap.xml", NULL }
		},
		{
			"Deny all /cgi-bin, /tmp + 2 sitemaps",
			"User-agent: *\n"
			"Disallow: /cgi-bin/\n"
			"Disallow: /tmp/\n"
			"Sitemap: http://www.example1.com/sitemap.xml\n"
			"Sitemap: http://www.example2.com/sitemap.xml",
			{ "/cgi-bin/", "/tmp/", NULL },
			{ "http://www.example1.com/sitemap.xml", "http://www.example2.com/sitemap.xml", NULL }
		},
		{
			"Deny all /cgi-bin, /tmp, /jumk + 3 sitemaps",
			"User-agent: *\n"
			"Disallow: /cgi-bin/\n"
			"Disallow: /tmp/\n"
			"Disallow: /junk/\n"
			"Sitemap: http://www.example1.com/sitemap.xml\n"
			"Sitemap: http://www.example2.com/sitemap.xml\n"
			"Sitemap: http://www.example3.com/sitemap.xml",
			{ "/cgi-bin/", "/tmp/", "/junk/" },
			{ "http://www.example1.com/sitemap.xml", "http://www.example2.com/sitemap.xml", "http://www.example3.com/sitemap.xml" }
		},
		{
			"Missing EOL",
			"User-agent: *\n"
			"Disallow: /cgi-bin/",
			{ "/cgi-bin/", NULL },
			{ NULL }
		},
	};

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];
		wget_robots *robots;
		int count;

		if (wget_robots_parse(&robots, t->input, PACKAGE_NAME) != WGET_E_SUCCESS) {
			info_printf("'%s': Failed to parse input\n", t->name);
			failed++;
			continue;
		}

		count = 0;
		for (unsigned it2 = 0; it2 < countof(test_data[it].path) && t->path[it2]; it2++, count++)
			;
		if (count != wget_robots_get_path_count(robots)) {
			info_printf("'%s': paths mismatch: expected %d, got %d\n",
				t->name, count, wget_robots_get_path_count(robots));
			failed++;
			goto next;
		}

		count = 0;
		for (unsigned it2 = 0; it2 < countof(test_data[it].sitemap) && t->sitemap[it2]; it2++, count++)
			;
		if (count != wget_robots_get_sitemap_count(robots)) {
			info_printf("'%s': sitemap # mismatch: expected %d, got %d\n",
				t->name, count, wget_robots_get_sitemap_count(robots));
			failed++;
			goto next;
		}

		for (unsigned it2 = 0; it2 < countof(test_data[it].path) && t->path[it2]; it2++) {
			int n = wget_robots_get_path_count(robots);
			for (int it3 = 0; it3 < n; it3++) {
				wget_string *paths = wget_robots_get_path(robots, it3);
				if (!strcmp(paths->p, t->path[it2])) {
				//	info_printf("Found path: \"%s\" on robots\n", t->path[it2]);
					it3 = n;
					ok++;
				} else if ((strcmp(paths->p, t->path[it2]) && it3 == n - 1)) {
					info_printf("'%s': Cannot find path: \"%s\" on robots\n", t->name, t->path[it2]);
					failed++;
				}
			}
		}

		for (unsigned it2 = 0; it2 < countof(test_data[it].sitemap) && t->sitemap[it2]; it2++) {
			int n = wget_robots_get_sitemap_count(robots);
			for (int it3 = 0; it3 < n; it3++) {
				const char *sitemaps = wget_robots_get_sitemap(robots, it3);
				if (!strcmp(sitemaps, t->sitemap[it2])) {
				//	info_printf("Found sitemap: \"%s\" on robots\n", t->sitemap[it2]);
					it3 = n;
					ok++;
				} else if ((strcmp(sitemaps, t->sitemap[it2]) && it3 == n - 1)) {
					info_printf("'%s': Cannot find sitemap: \"%s\" on robots\n", t->name, t->sitemap[it2]);
					failed++;
				}
			}
		}

next:
		wget_robots_free(&robots);
	}
}

static void test_set_proxy(void)
{
	static const struct test_data {
		const char *
			proxy;
		const char *
			encoding;
		int
			result;
	} test_data[] = {
		{ "http://192.168.8.253:3128", NULL, 1 },
		{ "  http://192.168.8.253:3128", NULL, 1 },
		{ "", NULL, 0 },
		{ " ", NULL, 0 },
		{ NULL, NULL, 0 },
		{ "http://192.168.8.253:3128,http://foo.xyz", NULL, 2},
		{ ",,", NULL, 0 },
		{ ", http://192.168.8.253:3128", NULL, 1 },
		{ ", http://192.168.8.253:3128 ,, http://foo.xyz", NULL, 2 },
	};

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];

		int n = wget_http_set_http_proxy(t->proxy, t->encoding);

		if (n == t->result)
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: wget_http_set_http_proxy(%s,%s) -> %d (expected %d)\n", it, t->proxy, t->encoding, n, t->result);
		}
	}

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];

		int n = wget_http_set_https_proxy(t->proxy, t->encoding);

		if (n == t->result)
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: wget_http_set_https_proxy(%s,%s) -> %d (expected %d)\n", it, t->proxy, t->encoding, n, t->result);
		}
	}
}


static void test_match_no_proxy(void)
{
	static const struct test_data {
		const char *
			no_proxy;
		const char *
			hostip;
		const char *
			encoding;
		int
			result;
	} test_data[] = {
		{ "10.250.192.78/12", "142.251.33.101", NULL, 0},
		{ "142.250.192.78/12", "142.251.33.101", NULL, 1},
		{ "142.250.192.78/50", "142.251.33.101", NULL, 0},
		{ "10.250.192.78.123/12", "142.251.33.101", NULL, 0},
		{ "142.250.192.78/32", "142.250.180.101", NULL, 0},
		{ "142.250.192.78/0", "142.250.180.101", NULL, 1},
		{ "142.250.192.78/-1", "142.250.180.101", NULL, 0},
		{ "", "142.250.180.101", NULL, 0},
		{ "142.251.33.101,10.250.192.78/12", "142.251.33.101", NULL, 1},
		{ "10.250.192.78/12, 142.251.33.101", "142.251.33.101", NULL, 1},
		{ "10.250.192.78/12, 142.251.33.101", "142.251.33.101", NULL, 1},
		{ "2402:9400:1234:5670::", "2402:9400:1234:5670::", NULL, 1},
		{ "2402:9400:1234:5670::", "2402:9400:1234:5671::", NULL, 0},
		{ "2402:9400:1234:5670::/60", "2402:9400:1234:5678::", NULL, 1},
		{ "2402:9400:1234:5670::/60", "2402:9400:1234:5680::", NULL, 0}
	};

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];
		wget_http_set_no_proxy(t->no_proxy, t->encoding);
		const wget_vector *no_proxies = wget_http_get_no_proxy();
		int n = wget_http_match_no_proxy(no_proxies, t->hostip);

		if (n == t->result) {
			ok++;
		} else {
			failed++;
			info_printf("Failed [%u]: wget_http_match_no_proxy(\"%s\",\"%s\") -> %d (expected %d)\n",
				it, t->no_proxy, t->hostip, n, t->result);
		}
	}
}

static void test_http_parse_full_date(void) {
	static const struct test_data {
		const char *
				date;
		uint64_t
				result;
	} test_data[] = {
		{"Sun, 25 May 2003 16:55:12 GMT", 1053881712},
		{"Wed, 09 Jun 2021 10:18:14 GMT", 1623233894}, // RFC 822 / 1123
		{"Wednesday, 09-Jun-21 10:18:14", 1623233894}, // RFC 850 / 1036 or Netscape
		{"Wed, 09-Jun-21 10:18:14", 1623233894}, // RFC 850 / 1036 or Netscape
		{"Wed Jun 09 10:18:14 2021", 1623233894}, // ANSI C's asctime()
		{"1 Mar 2027 09:23:12 GMT", 1803892992}, // non-standard
		{"Sun Nov 26 2023 21:24:47", 1701033887}, // non-standard
	};

	for (unsigned it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];
		uint64_t ts = wget_http_parse_full_date(t->date);

		if (ts == t->result) {
			ok++;
		} else {
			failed++;
			info_printf("Failed [%u]: wget_http_parse_full_date(\"%s\") -> %"PRIu64" (expected %"PRIu64")\n",
						it, t->date, ts, t->result);
		}
	}
}

// Add some corner cases here.
static void test_parse_header_line(void)
{
	const char *filename;

	// from https://github.com/rockdaboot/wget2/issues/235
	wget_http_parse_content_disposition("attachment; filename=\"with space\"", &filename);

	if (strcmp(filename, "with space") == 0) {
		ok++;
	} else {
		failed++;
		info_printf("HTTP keep-alive Connection header could not be set.\n");
	}

	xfree(filename);
}

static void test_parse_response_header(void)
{
	char *response_text = wget_strdup(
			"HTTP/1.1 200 OK\r\n"\
			"Server: Apache/2.2.22 (Debian)\r\n"\
			"Date: Sun, 11 Jun 2017 09:45:54 GMT\r\n"\
			"Content-Length: 476\r\n"\
			"Connection: keep-alive\r\n"\
			"X-Archive-Orig-last-modified: Sun, 25 May 2003 16:55:12 GMT\r\n"\
			"Content-Type: text/plain; charset=utf-8\r\n\r\n");

	wget_http_response *resp = wget_http_parse_response_header(response_text);

	if (resp->keep_alive)
		ok++;
	else {
		failed++;
		info_printf("HTTP keep-alive Connection header could not be set.\n");
	}

	if (resp->content_length == 476)
		ok++;
	else {
		failed++;
		info_printf("Content-Length mismatch.\n");
	}

	if (!strcmp(resp->content_type, "text/plain"))
		ok++;
	else {
		failed++;
		info_printf("Content-Type mismatch.\n");
	}

	if (resp->last_modified == wget_http_parse_full_date("Sun, 25 May 2003 16:55:12 GMT"))
		ok++;
	else {
		failed++;
		info_printf("X-Archive-Orig-last-modified mismatch\n");
	}

	xfree(resp->content_type);
	xfree(resp->content_type_encoding);
	xfree(resp);
	xfree(response_text);
}

static unsigned alloc_flags;

static void *test_malloc(size_t size)
{
	alloc_flags |= 1;
	return malloc(size) ; // space before ; is intentional to trick out syntax-check
}

static void *test_calloc(size_t nmemb, size_t size)
{
	alloc_flags |= 2;
	return calloc(nmemb, size) ; // space before ; is intentional to trick out syntax-check
}

static void *test_realloc(void *ptr, size_t size)
{
	alloc_flags |= 4;
	return realloc(ptr, size) ; // space before ; is intentional to trick out syntax-check
}

static void test_free(void *ptr)
{
	alloc_flags |= 8;
	free(ptr);
}

int main(int argc, const char **argv)
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

	if (init(argc, argv) < 0) // allows us to test with options (e.g. with --debug)
		return -1;

	srand((unsigned int) time(NULL));
	wget_malloc_fn = test_malloc;
	wget_calloc_fn = test_calloc;
	wget_realloc_fn = test_realloc;
	wget_free = test_free;

	// testing basic library functionality
	test_mem();
	test_strlcpy();
	test_strscpy();
	test_buffer();
	test_buffer_printf();
	test_utils();
	test_strcasecmp_ascii();
	test_hashing();
	test_vector();
	test_stringmap();
	test_striconv();
	test_bitmap();

	if (failed) {
		info_printf("ERROR: %d out of %d basic tests failed\n", failed, ok + failed);
		info_printf("This may completely break Wget functionality !!!\n");
		return 1;
	}

	test_iri_parse();
//	test_iri_parse_urltests();
	test_iri_relative_to_absolute();
	test_iri_compare();
	test_parser();
	test_match_no_proxy();
	test_cookies();
	test_hsts();
	test_hpkp();
	test_parse_challenge();
	test_bar();
	test_netrc();
	test_robots();
	test_set_proxy();
	test_parse_response_header();
	test_parse_header_line();
	test_http_parse_full_date();

	selftest_options() ? failed++ : ok++;

	deinit(); // free resources allocated by init()

	if (alloc_flags == 0xF)
		ok++;
	else {
		failed++;
		info_printf("alloc_flags %X\n", alloc_flags);
	}

	if (failed) {
		info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}

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
 * test routines
 *
 * Source Code License
 *   CC0 1.0 Universal (CC0 1.0) Public Domain Dedication
 *   http://creativecommons.org/publicdomain/zero/1.0/legalcode
 *
 * Changelog
 * 06.07.2012  Tim Ruehsen  created
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

#include "../xalloc.h"
#include "../utils.h"
#include "../options.h"
#include "../css.h"
#include "../xml.h"
#include "../iri.h"
#include "../log.h"
#include "../net.h"
#include "../vector.h"
#include "../buffer.h"

static int
	ok,
	failed;

static void _test_buffer(buffer_t *buf, const char *name)
{
	char test[256];
	int it;

	for (it = 0; it < sizeof(test)-1; it++) {
		test[it] = 'a' + it % 26;
		test[it + 1] = 0;

		buffer_strcpy(buf, test);
		buffer_strcat(buf, test);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.1 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		buffer_memcpy(buf, test, it + 1);
		buffer_memcat(buf, test, it + 1);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.2 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		buffer_printf(buf, "%s%s", test, test);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.3 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		buffer_printf(buf, "%s", test);
		buffer_append_printf(buf, "%s", test);

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
	char buf_static[16];
	buffer_t buf, *bufp;

	// testing buffer on stack, using initial stack memory
	// without resizing

	buffer_init(&buf, buf_static, sizeof(buf_static));
	buffer_deinit(&buf);

	// testing buffer on stack, using initial stack memory
	// with resizing

	buffer_init(&buf, buf_static, sizeof(buf_static));
	_test_buffer(&buf, "Test 1");
	buffer_deinit(&buf);

	// testing buffer on stack, using initial heap memory
	// without resizing

	buffer_init(&buf, NULL, 16);
	buffer_deinit(&buf);

	// testing buffer on stack, using initial heap memory
	// with resizing

	buffer_init(&buf, NULL, 16);
	_test_buffer(&buf, "Test 2");
	buffer_deinit(&buf);

	// testing buffer on heap, using initial stack memory
	// without resizing

	bufp = buffer_init(NULL, buf_static, sizeof(buf_static));
	buffer_deinit(bufp);

	bufp = buffer_init(NULL, buf_static, sizeof(buf_static));
	buffer_free(&bufp);

	// testing buffer on heap, using initial stack memory
	// with resizing

	bufp = buffer_init(NULL, buf_static, sizeof(buf_static));
	_test_buffer(bufp, "Test 3");
	buffer_deinit(bufp);

	bufp = buffer_init(NULL, buf_static, sizeof(buf_static));
	_test_buffer(bufp, "Test 4");
	buffer_free(&bufp);

	// testing buffer on heap, using initial heap memory
	// without resizing

	bufp = buffer_alloc(16);
	buffer_free(&bufp);

	// testing buffer on heap, using initial heap memory
	// with resizing

	bufp = buffer_alloc(16);
	_test_buffer(bufp, "Test 5");
	buffer_free(&bufp);
}

static void test_buffer_printf(void)
{
	char buf_static[32];
	buffer_t buf;

	// testing buffer_printf() by comparing it with C standard function sprintf()

	static const char *zero_padded[] = { "", "0" };
	static const char *left_adjust[] = { "", "-" };
	static const long long number[] = { 0, 1, -1, 10, -10, 18446744073709551615ULL };
	static const char *modifier[] = { "", "h", "hh", "l", "ll", "L", "z" };
	static const char *conversion[] = { "d", "i", "u", "o", "x", "X" };
	char fmt[32], result[32], string[32];
	size_t z, a, it, n, c, m;
	int width, precision;

	buffer_init(&buf, buf_static, sizeof(buf_static));

	for (z = 0; z < countof(zero_padded); z++) {
		for (a = 0; a < countof(left_adjust); a++) {
			for (width = -1; width < 12; width++) {
				for (precision = -1; precision < 12; precision++) {

					// testing %s stuff

					if (width == -1) {
						if (precision == -1) {
							sprintf(fmt,"%%%s%ss", left_adjust[a], zero_padded[z]);
						} else {
							sprintf(fmt,"%%%s%s.%ds", left_adjust[a], zero_padded[z], precision);
						}
					} else {
						if (precision == -1) {
							sprintf(fmt,"%%%s%s%ds", left_adjust[a], zero_padded[z], width);
						} else {
							sprintf(fmt,"%%%s%s%d.%ds", left_adjust[a], zero_padded[z], width, precision);
						}
					}

					for (it = 0; it < sizeof(string); it++) {
						memset(string, 'a', it);
						string[it] = 0;

						#pragma GCC diagnostic push
						#pragma GCC diagnostic ignored "-Wformat-nonliteral"
						sprintf(result, fmt, string);
						buffer_printf2(&buf, fmt, string);
						#pragma GCC diagnostic pop

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
							sprintf(fmt,"%%%s%ss", left_adjust[a], zero_padded[z]);
						} else {
							sprintf(fmt,"%%%s%s.*s", left_adjust[a], zero_padded[z]);
						}
					} else {
						if (precision == -1) {
							sprintf(fmt,"%%%s%s*s", left_adjust[a], zero_padded[z]);
						} else {
							sprintf(fmt,"%%%s%s*.*s", left_adjust[a], zero_padded[z]);
						}
					}

					for (it = 0; it < sizeof(string); it++) {
						memset(string, 'a', it);
						string[it] = 0;

						#pragma GCC diagnostic push
						#pragma GCC diagnostic ignored "-Wformat-nonliteral"
						if (width == -1) {
							if (precision == -1) {
								sprintf(result, fmt, string);
								buffer_printf2(&buf, fmt, string);
							} else {
								sprintf(result, fmt, precision, string);
								buffer_printf2(&buf, fmt, precision, string);
							}
						} else {
							if (precision == -1) {
								sprintf(result, fmt, width, string);
								buffer_printf2(&buf, fmt, width, string);
							} else {
								sprintf(result, fmt, width, precision, string);
								buffer_printf2(&buf, fmt, width, precision, string);
							}
						}
						#pragma GCC diagnostic pop

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

					for (m = 0; m < countof(modifier); m++) {
					for (c = 0; c < countof(conversion); c++) {
						if (width == -1) {
							if (precision == -1) {
								sprintf(fmt,"%%%s%s%s%s", left_adjust[a], zero_padded[z], modifier[m], conversion[c]);
							} else {
								sprintf(fmt,"%%%s%s.%d%s%s", left_adjust[a], zero_padded[z], precision, modifier[m], conversion[c]);
							}
						} else {
							if (precision == -1) {
								sprintf(fmt,"%%%s%s%d%s%s", left_adjust[a], zero_padded[z], width, modifier[m], conversion[c]);
							} else {
								sprintf(fmt,"%%%s%s%d.%d%s%s", left_adjust[a], zero_padded[z], width, precision, modifier[m], conversion[c]);
							}
						}

						for (n = 0; n < countof(number); n++) {
							#pragma GCC diagnostic push
							#pragma GCC diagnostic ignored "-Wformat-nonliteral"
							sprintf(result, fmt, number[n]);
							buffer_printf2(&buf, fmt, number[n]);
							#pragma GCC diagnostic pop

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

	buffer_deinit(&buf);
}

static void test_iri_parse(void)
{
	const struct iri_test_data {
		const char
			*uri,
			*display,
			*scheme,
			*userinfo,
			*password,
			*host,
			*port,
			*path,
			*query,
			*fragment;
	} test_data[] = {
		{ "//example.com/thepath", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, "thepath", NULL, NULL},
		{ "///thepath", NULL, IRI_SCHEME_HTTP, NULL, NULL, NULL, NULL, "thepath", NULL, NULL},
		{ "example.com", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "http://example.com", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "https://example.com", NULL, IRI_SCHEME_HTTPS, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "http://example.com:80", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", "80", NULL, NULL, NULL},
		{ "http://example.com:80/index.html", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", "80", "index.html", NULL, NULL},
		{ "http://example.com:80/index.html?query#frag", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", "80", "index.html", "query", "frag"},
		{ "http://example.com:80/index.html?#", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", "80", "index.html", "", ""},
		{ "碼標準萬國碼.com", NULL, IRI_SCHEME_HTTP, NULL, NULL, "碼標準萬國碼.com", NULL, NULL, NULL, NULL},
		//		{ "ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm", NULL,"ftp",NULL,NULL,"cnn.example.com",NULL,NULL,"story=breaking_news@10.0.0.1/top_story.htm",NULL }
		{ "ftp://cnn.example.com?story=breaking_news@10.0.0.1/top_story.htm", NULL, "ftp", NULL, NULL, "cnn.example.com", NULL, NULL, "story=breaking_news@10.0.0.1/top_story.htm", NULL}
	};
	size_t it;

	for (it = 0; it < countof(test_data); it++) {
		const struct iri_test_data *t = &test_data[it];
		IRI *iri = iri_parse(t->uri);

		if (null_strcmp(iri->display, t->display)
			|| null_strcmp(iri->scheme, t->scheme)
			|| null_strcmp(iri->userinfo, t->userinfo)
			|| null_strcmp(iri->password, t->password)
			|| null_strcmp(iri->host, t->host)
			|| null_strcmp(iri->port, t->port)
			|| null_strcmp(iri->path, t->path)
			|| null_strcmp(iri->query, t->query)
			|| null_strcmp(iri->fragment, t->fragment)) {
			failed++;
			printf("IRI test #%zu failed:\n", it + 1);
			printf(" [%s]\n", iri->uri);
			printf("  display %s (expected %s)\n", iri->display, t->display);
			printf("  scheme %s (expected %s)\n", iri->scheme, t->scheme);
			printf("  user %s (expected %s)\n", iri->userinfo, t->userinfo);
			printf("  host %s (expected %s)\n", iri->host, t->host);
			printf("  port %s (expected %s)\n", iri->port, t->port);
			printf("  path %s (expected %s)\n", iri->path, t->path);
			printf("  query %s (expected %s)\n", iri->query, t->query);
			printf("  fragment %s (expected %s)\n", iri->fragment, t->fragment);
			printf("\n");
		} else {
			ok++;
		}

		iri_free(&iri);
	}
}

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
	size_t it;
	char tag_buf[16];
	const char *tag;
	char uri_buf_static[32]; // use a size that forces allocation in some cases
	buffer_t *uri_buf = 	buffer_init(NULL, uri_buf_static, sizeof(uri_buf_static));
	IRI *base;

	for (it = 0; it < countof(test_data); it++) {
		const struct iri_test_data *t = &test_data[it];

		base = iri_parse(t->base);
		tag = iri_get_connection_part(base, tag_buf, sizeof(tag_buf));

		iri_relative_to_absolute(base, tag, t->relative, strlen(t->relative), uri_buf);

		if (!strcmp(uri_buf->data, t->result))
			ok++;
		else {
			failed++;
			info_printf("Failed [%zu]: %s+%s -> %s (expected %s)\n", it, t->base, t->relative, uri_buf->data, t->result);
		}
/*
		if (!strncmp(t->relative, "http:", 5) && !strcmp(uri_buf->data, t->result))
			ok++;
		else if (!strncmp(t->relative, "//", 2) && !strcmp(uri_buf->data, t->result))
			ok++;
		else if (HOST[sizeof(HOST)-2] == '/' && !strcmp(uri_buf->data + sizeof(HOST) - 1, t->result))
			ok++;
		else if (!strcmp(uri_buf->data + sizeof(HOST), t->result))
			ok++;
		else {
			failed++;
			info_printf("Failed [%zu]: %zu '%s' '%s'\n", it, sizeof(HOST), uri_buf->data + sizeof(HOST) - 1, t->result);
			info_printf("Failed [%zu]: %s -> %s (expected %s/%s)\n", it, t->relative, uri_buf->data, HOST, t->result);
		}
*/
		if (tag != tag_buf)
			xfree(tag);

		iri_free(&base);
	}

	buffer_free(&uri_buf);
}

static void css_dump(UNUSED void *user_ctx, const char *url, size_t len)
{
	log_printf("*** %zu '%.*s'\n", len, (int)len, url);
}

static void test_parser(void)
{
	DIR *dirp;
	struct dirent *dp;
	const char *ext;
	char fname[128];
	int xml = 0, html = 0, css = 0;

	// test the XML / HTML parser, you should start the test with valgrind
	// to detect memory faults
	if ((dirp = opendir("files")) != NULL) {
		while ((dp = readdir(dirp)) != NULL) {
			if (*dp->d_name == '.') continue;
			if ((ext = strrchr(dp->d_name, '.'))) {
				snprintf(fname, sizeof(fname), "files/%s", dp->d_name);
				info_printf("parsing %s\n", fname);
				if (!strcasecmp(ext, ".xml")) {
					xml_parse_file(fname, NULL, NULL, 0);
					xml++;
				} else if (!strcasecmp(ext, ".html")) {
					html_parse_file(fname, NULL, NULL, 0);
					html++;
				} else if (!strcasecmp(ext, ".css")) {
					css_parse_file(fname, css_dump, NULL);
					css++;
				}
			}
		}
		closedir(dirp);
	}

	info_printf("%d XML, %d HTML and %d CSS files parsed\n", xml, html, css);
}

static void test_utils(void)
{
	int it, ndst;
	unsigned char src[1];
	char dst1[3], dst2[3];

	for (ndst = 1; ndst <= 3; ndst++) {
		for (it = 0; it <= 255; it++) {
			src[0] = it;
			buffer_to_hex(src, 1, dst1, ndst);
			snprintf(dst2, ndst, "%02x", src[0]);
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

struct ENTRY {
	const char
		*txt;
};

static int compare_txt(struct ENTRY *a1, struct ENTRY *a2)
{
	return strcasecmp(a1->txt, a2->txt);
}

static void test_vector(void)
{
	struct ENTRY
		*tmp,
		txt_sorted[5] = { {""}, {"four"}, {"one"}, {"three"}, {"two"} },
		*txt[countof(txt_sorted)];
	VECTOR
		*v = vec_create(2, -2, (int(*)(const void *, const void *))compare_txt);
	size_t
		it;
	int
		n;

	// copy
	for (it = 0; it < countof(txt); it++)
		txt[it] = &txt_sorted[it];

	// shuffle txt
	for (it = 0; it < countof(txt); it++) {
		n = rand()%countof(txt);
		tmp = txt[n];
		txt[n] = txt[it];
		txt[it] = tmp;
	}

	for (it = 0; it < countof(txt); it++) {
		vec_insert_sorted(v, txt[it], sizeof(struct ENTRY));
	}

	for (it = 0; it < countof(txt); it++) {
		struct ENTRY *e = vec_get(v, it);
		if (!strcmp(e->txt,txt_sorted[it].txt))
			ok++;
		else
			failed++;
	}

	vec_free(&v);
}

int main(int argc, const char * const *argv)
{
	init(argc, argv); // allows us to test with options (e.g. with --debug)

	srand(time(NULL));

	// testing basic library functionality
	test_buffer();
	test_buffer_printf();
	test_vector();
	test_utils();

	if (failed) {
		info_printf("ERROR: %d out of %d basic tests failed\n", failed, ok + failed);
		info_printf("This may completely break Mget functionality !!!\n");
		return 1;
	}

	test_iri_parse();
	test_iri_relative_to_absolute();
	test_parser();

	// free some resources to minimize valgrind output
	tcp_set_dns_caching(0); // frees DNS cache

	if (failed) {
		info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	selftest_options() ? failed++: ok++;

	info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}

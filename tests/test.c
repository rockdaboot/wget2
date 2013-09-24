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
 * Changelog
 * 06.07.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

#include <libmget.h>
#include "../libmget/private.h"

#include "../src/options.h"
#include "../src/log.h"

static int
	ok,
	failed;

static void _test_buffer(mget_buffer_t *buf, const char *name)
{
	char test[256];
	int it;

	for (it = 0; it < (int)sizeof(test)-1; it++) {
		test[it] = 'a' + it % 26;
		test[it + 1] = 0;

		mget_buffer_strcpy(buf, test);
		mget_buffer_strcat(buf, test);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.1 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		mget_buffer_memcpy(buf, test, it + 1);
		mget_buffer_memcat(buf, test, it + 1);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.2 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		mget_buffer_printf(buf, "%s%s", test, test);

		if (!strncmp(buf->data, test, it + 1) && !strncmp(buf->data + it + 1, test, it + 1)) {
			ok++;
		} else {
			failed++;
			info_printf("test_buffer.3 '%s': [%d] got %s (expected %s%s)\n", name, it, buf->data, test, test);
		}

		mget_buffer_printf(buf, "%s", test);
		mget_buffer_printf_append(buf, "%s", test);

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
	mget_buffer_t buf, *bufp;

	// testing buffer on stack, using initial stack memory
	// without resizing

	mget_buffer_init(&buf, buf_static, sizeof(buf_static));
	mget_buffer_deinit(&buf);

	// testing buffer on stack, using initial stack memory
	// with resizing

	mget_buffer_init(&buf, buf_static, sizeof(buf_static));
	_test_buffer(&buf, "Test 1");
	mget_buffer_deinit(&buf);

	// testing buffer on stack, using initial heap memory
	// without resizing

	mget_buffer_init(&buf, NULL, 16);
	mget_buffer_deinit(&buf);

	// testing buffer on stack, using initial heap memory
	// with resizing

	mget_buffer_init(&buf, NULL, 16);
	_test_buffer(&buf, "Test 2");
	mget_buffer_deinit(&buf);

	// testing buffer on heap, using initial stack memory
	// without resizing

	bufp = mget_buffer_init(NULL, buf_static, sizeof(buf_static));
	mget_buffer_deinit(bufp);

	bufp = mget_buffer_init(NULL, buf_static, sizeof(buf_static));
	mget_buffer_free(&bufp);

	// testing buffer on heap, using initial stack memory
	// with resizing

	bufp = mget_buffer_init(NULL, buf_static, sizeof(buf_static));
	_test_buffer(bufp, "Test 3");
	mget_buffer_deinit(bufp);

	bufp = mget_buffer_init(NULL, buf_static, sizeof(buf_static));
	_test_buffer(bufp, "Test 4");
	mget_buffer_free(&bufp);

	// testing buffer on heap, using initial heap memory
	// without resizing

	bufp = mget_buffer_alloc(16);
	mget_buffer_free(&bufp);

	// testing buffer on heap, using initial heap memory
	// with resizing

	bufp = mget_buffer_alloc(16);
	_test_buffer(bufp, "Test 5");
	mget_buffer_free(&bufp);

	// check that appending works

	mget_buffer_init(&buf, buf_static, sizeof(buf_static));
	mget_buffer_strcpy(&buf, "A");
	mget_buffer_strcat(&buf, "B");
	mget_buffer_memcat(&buf, "C", 1);
	mget_buffer_memset_append(&buf, 'D', 1);
	mget_buffer_printf_append2(&buf, "%s", "E");
	if (!strcmp(buf.data, "ABCDE"))
		ok++;
	else {
		failed++;
		info_printf("test_buffer.append: got %s (expected %s)\n", buf.data, "ABCDE");
	}
	mget_buffer_deinit(bufp);

}

static void test_buffer_printf(void)
{
	char buf_static[32];
	mget_buffer_t buf;

	// testing buffer_printf() by comparing it with C standard function sprintf()

	static const char *zero_padded[] = { "", "0" };
	static const char *left_adjust[] = { "", "-" };
	static const long long number[] = { 0, 1LL, -1LL, 10LL, -10LL, 18446744073709551615ULL };
	static const char *modifier[] = { "", "h", "hh", "l", "ll", "z" }; // %L... won't work on OpenBSD5.0
	static const char *conversion[] = { "d", "i", "u", "o", "x", "X" };
	char fmt[32], result[64], string[32];
	size_t z, a, it, n, c, m;
	int width, precision;

	mget_buffer_init(&buf, buf_static, sizeof(buf_static));

	mget_buffer_printf2(&buf, "%s://%s", "http", "host");
	if (strcmp("http://host", buf.data)) {
		failed++;
		info_printf("%s: Failed with format ('%%s://%%s','http','host'): '%s' != 'http://host'\n", __func__, buf.data);
		return;
	} else
		ok++;

	for (z = 0; z < countof(zero_padded); z++) {
		for (a = 0; a < countof(left_adjust); a++) {
			for (width = -1; width < 12; width++) {
				for (precision = -1; precision < 12; precision++) {

					// testing %s stuff

					if (width == -1) {
						if (precision == -1) {
							sprintf(fmt,"abc%%%s%ssxyz", left_adjust[a], zero_padded[z]);
						} else {
							sprintf(fmt,"abc%%%s%s.%dsxyz", left_adjust[a], zero_padded[z], precision);
						}
					} else {
						if (precision == -1) {
							sprintf(fmt,"abc%%%s%s%dsxyz", left_adjust[a], zero_padded[z], width);
						} else {
							sprintf(fmt,"abc%%%s%s%d.%dsxyz", left_adjust[a], zero_padded[z], width, precision);
						}
					}

					for (it = 0; it < sizeof(string); it++) {
						memset(string, 'a', it);
						string[it] = 0;

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
						#pragma GCC diagnostic push
						#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
						sprintf(result, fmt, string);
						mget_buffer_printf2(&buf, fmt, string);
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
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

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
						#pragma GCC diagnostic push
						#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
						if (width == -1) {
							if (precision == -1) {
								sprintf(result, fmt, string);
								mget_buffer_printf2(&buf, fmt, string);
							} else {
								sprintf(result, fmt, precision, string);
								mget_buffer_printf2(&buf, fmt, precision, string);
							}
						} else {
							if (precision == -1) {
								sprintf(result, fmt, width, string);
								mget_buffer_printf2(&buf, fmt, width, string);
							} else {
								sprintf(result, fmt, width, precision, string);
								mget_buffer_printf2(&buf, fmt, width, precision, string);
							}
						}
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
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
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
							#pragma GCC diagnostic push
							#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
							sprintf(result, fmt, number[n]);
							mget_buffer_printf2(&buf, fmt, number[n]);
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
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

	mget_buffer_deinit(&buf);
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
		{ "1.2.3.4", NULL, IRI_SCHEME_HTTP, NULL, NULL, "1.2.3.4", NULL, NULL, NULL, NULL},
		{ "1.2.3.4:987", NULL, IRI_SCHEME_HTTP, NULL, NULL, "1.2.3.4", "987", NULL, NULL, NULL},
		{ "//example.com/thepath", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, "thepath", NULL, NULL},
		// { "///thepath", NULL, IRI_SCHEME_HTTP, NULL, NULL, NULL, NULL, "thepath", NULL, NULL},
		{ "example.com", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "example.com:555", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", "555", NULL, NULL, NULL},
		{ "http://example.com", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "http://example.com:", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "http://example.com:/", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, "", NULL, NULL},
		{ "http://example.com:80/", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, "", NULL, NULL},
		{ "https://example.com", NULL, IRI_SCHEME_HTTPS, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "https://example.com:443", NULL, IRI_SCHEME_HTTPS, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "https://example.com:444", NULL, IRI_SCHEME_HTTPS, NULL, NULL, "example.com", "444", NULL, NULL, NULL},
		{ "http://example.com:80", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "http://example.com:81", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", "81", NULL, NULL, NULL},
		{ "http://example.com/index.html", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, "index.html", NULL, NULL},
		{ "http://example.com/index.html?query#frag", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, "index.html", "query", "frag"},
		{ "http://example.com/index.html?#", NULL, IRI_SCHEME_HTTP, NULL, NULL, "example.com", NULL, "index.html", "", ""},
		{ "碼標準萬國碼.com", NULL, IRI_SCHEME_HTTP, NULL, NULL, "xn--9cs565brid46mda086o.com", NULL, NULL, NULL, NULL},
		//		{ "ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm", NULL,"ftp",NULL,NULL,"cnn.example.com",NULL,NULL,"story=breaking_news@10.0.0.1/top_story.htm",NULL }
		{ "ftp://cnn.example.com?story=breaking_news@10.0.0.1/top_story.htm", NULL, "ftp", NULL, NULL, "cnn.example.com", NULL, NULL, "story=breaking_news@10.0.0.1/top_story.htm", NULL}
	};
	unsigned it;

	for (it = 0; it < countof(test_data); it++) {
		const struct iri_test_data *t = &test_data[it];
		MGET_IRI *iri = mget_iri_parse(t->uri, "utf-8");

		if (mget_strcmp(iri->display, t->display)
			|| mget_strcmp(iri->scheme, t->scheme)
			|| mget_strcmp(iri->userinfo, t->userinfo)
			|| mget_strcmp(iri->password, t->password)
			|| mget_strcmp(iri->host, t->host)
			|| mget_strcmp(iri->port, t->port)
			|| mget_strcmp(iri->path, t->path)
			|| mget_strcmp(iri->query, t->query)
			|| mget_strcmp(iri->fragment, t->fragment))
		{
			failed++;
			printf("IRI test #%u failed:\n", it + 1);
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

		mget_iri_free(&iri);
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
	unsigned it;
	char uri_buf_static[32]; // use a size that forces allocation in some cases
	mget_buffer_t *uri_buf = 	mget_buffer_init(NULL, uri_buf_static, sizeof(uri_buf_static));
	MGET_IRI *base;

	for (it = 0; it < countof(test_data); it++) {
		const struct iri_test_data *t = &test_data[it];

		base = mget_iri_parse(t->base, "utf-8");
		mget_iri_relative_to_abs(base, t->relative, strlen(t->relative), uri_buf);

		if (!strcmp(uri_buf->data, t->result))
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: %s+%s -> %s (expected %s)\n", it, t->base, t->relative, uri_buf->data, t->result);
		}

		mget_iri_free(&base);
	}

	mget_buffer_free(&uri_buf);
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
		MGET_IRI *iri1 = mget_iri_parse(t->url1, "utf-8");
		MGET_IRI *iri2 = mget_iri_parse(t->url2, "utf-8");

		n = mget_iri_compare(iri1, iri2);
		if (n < -1) n = -1;
		else if (n > 1) n = 1;

		if (n == t->result)
			ok++;
		else {
			failed++;
			info_printf("Failed [%u]: compare(%s,%s) -> %d (expected %d)\n", it, t->url1, t->url2, n, t->result);
		}

		mget_iri_free(&iri2);
		mget_iri_free(&iri1);
	}
}

static void _css_dump_charset(G_GNUC_MGET_UNUSED void *user_ctx, const char *encoding, size_t len)
{
	debug_printf(_("URI content encoding = '%.*s'\n"), (int)len, encoding);
}

static void _css_dump_uri(G_GNUC_MGET_UNUSED void *user_ctx, const char *url, size_t len, G_GNUC_MGET_UNUSED size_t pos)
{
	debug_printf("*** %zu '%.*s'\n", len, (int)len, url);
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
	if ((dirp = opendir(SRCDIR "/files")) != NULL) {
		while ((dp = readdir(dirp)) != NULL) {
			if (*dp->d_name == '.') continue;
			if ((ext = strrchr(dp->d_name, '.'))) {
				snprintf(fname, sizeof(fname), SRCDIR "/files/%s", dp->d_name);
				if (!strcasecmp(ext, ".xml")) {
					info_printf("parsing %s\n", fname);
					mget_xml_parse_file(fname, NULL, NULL, 0);
					xml++;
				}
/*				else if (!strcasecmp(ext, ".html")) {
					info_printf("parsing %s\n", fname);
					mget_html_parse_file(fname, NULL, NULL, 0);
					html++;
				}
				else if (!strcasecmp(ext, ".css")) {
					info_printf("parsing %s\n", fname);
					mget_css_parse_file(fname, _css_dump_uri, _css_dump_charset, NULL);
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
	static const struct test_data {
		const char
			*uri,
			*set_cookie,
			*name, *value, *domain, *path, *expires;
		unsigned int
			domain_dot : 1, // for compatibility with Netscape cookie format
			normalized : 1,
			persistent : 1,
			host_only : 1,
			secure_only : 1, // cookie should be used over secure connections only (TLS/HTTPS)
			http_only : 1; // just use the cookie via HTTP/HTTPS protocol
		int
			result;
	} test_data[] = {
		{	// allowed cookie
			"www.example.com",
			"ID=65=abcd; expires=Tuesday, 07-May-2013 07:48:53 GMT; path=/; domain=.example.com; HttpOnly",
			"ID", "65=abcd", "example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			1, 1, 1, 0, 0, 1,
			1
		},
		{	// allowed cookie ANSI C's asctime format
			"www.example.com",
			"ID=65=abcd; expires=Tue May 07 07:48:53 2013; path=/; domain=.example.com",
			"ID", "65=abcd", "example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			1, 1, 1, 0, 0, 0,
			1
		},
		{	// allowed cookie without path
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; domain=.example.com",
			"ID", "65=abcd", "example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			1, 1, 1, 0, 0, 0,
			1
		},
		{	// allowed cookie without domain
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; path=/",
			"ID", "65=abcd", "www.example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			0, 1, 1, 1, 0, 0,
			1
		},
		{	// allowed cookie without domain, path and expires
			"www.example.com",
			"ID=65=abcd",
			"ID", "65=abcd", "www.example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			0, 1, 0, 1, 0, 0,
			1
		},
		{	// illegal cookie
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; path=/; domain=.example.org",
			"ID", "65=abcd", "example.org", "/", "Tue, 07 May 2013 07:48:53 GMT",
			1, 0, 1, 0, 0, 0,
			0
		},
		{	// supercookie, not accepted by normalization (rule 'com')
			"www.example.com",
			"ID=65=abcd; expires=Mon, 29-Feb-2016 07:48:54 GMT; path=/; domain=.com; HttpOnly; Secure",
			"ID", "65=abcd", "com", "/", "Mon, 29 Feb 2016 07:48:54 GMT",
			1, 0, 1, 0, 1, 1,
			0
		},
		{	// supercookie, not accepted by normalization  (rule '*.ar')
			"www.example.ar",
			"ID=65=abcd; expires=Tue, 29-Feb-2000 07:48:55 GMT; path=/; domain=.example.ar",
			"ID", "65=abcd", "example.ar", "/", "Tue, 29 Feb 2000 07:48:55 GMT",
			1, 0, 1, 0, 0, 0,
			0
		},
		{	// exception rule '!educ.ar', accepted by normalization
			"www.educ.ar",
			"ID=65=abcd; path=/; domain=.educ.ar",
			"ID", "65=abcd", "educ.ar", "/", NULL,
			1, 1, 0, 0, 0, 0,
			1
		},
	};
	MGET_COOKIE cookie;
	MGET_IRI *iri;
	unsigned it;
	int result;

	mget_cookie_load_public_suffixes(DATADIR "/public_suffixes.txt");

	for (it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];
		char thedate[32];

		iri = mget_iri_parse(t->uri, "utf-8");
		http_parse_setcookie(t->set_cookie, &cookie);
		if ((result = mget_cookie_normalize_cookie(iri, &cookie)) != t->result) {
			failed++;
			info_printf("Failed [%u]: normalize_cookie(%s) -> %d (expected %d)\n", it, t->set_cookie, result, t->result);
			goto next;
		}

		if (cookie.expires) {
			http_print_date(cookie.expires, thedate, sizeof(thedate));
			if (strcmp(thedate, t->expires)) {
				failed++;
				info_printf("Failed [%u]: expires mismatch: '%s' != '%s' (time_t %lld)\n", it, thedate, t->expires, (long long)cookie.expires);
				goto next;
			}
		}

		if (strcmp(cookie.name, t->name) ||
			strcmp(cookie.value, t->value) ||
			strcmp(cookie.domain, t->domain) ||
			strcmp(cookie.path, t->path) ||
			cookie.domain_dot != t->domain_dot ||
			cookie.normalized != t->normalized ||
			cookie.persistent != t->persistent ||
			cookie.host_only != t->host_only ||
			cookie.secure_only != t->secure_only ||
			cookie.http_only != t->http_only)
		{
			failed++;

			info_printf("Failed [%u]: cookie (%s) differs:\n", it, t->set_cookie);
			if (strcmp(cookie.name, t->name))
				info_printf("  name %s (expected %s)\n", cookie.name, t->name);
			if (strcmp(cookie.value, t->value))
				info_printf("  value %s (expected %s)\n", cookie.value, t->value);
			if (strcmp(cookie.domain, t->domain))
				info_printf("  domain %s (expected %s)\n", cookie.domain, t->domain);
			if (strcmp(cookie.path, t->path))
				info_printf("  path %s (expected %s)\n", cookie.path, t->path);
			if (cookie.domain_dot != t->domain_dot)
				info_printf("  domain_dot %d (expected %d)\n", cookie.domain_dot, t->domain_dot);
			if (cookie.normalized != t->normalized)
				info_printf("  normalized %d (expected %d)\n", cookie.normalized, t->normalized);
			if (cookie.persistent != t->persistent)
				info_printf("  persistent %d (expected %d)\n", cookie.persistent, t->persistent);
			if (cookie.host_only != t->host_only)
				info_printf("  host_only %d (expected %d)\n", cookie.host_only, t->host_only);
			if (cookie.secure_only != t->secure_only)
				info_printf("  secure_only %d (expected %d)\n", cookie.secure_only, t->secure_only);
			if (cookie.http_only != t->http_only)
				info_printf("  http_only %d (expected %d)\n", cookie.http_only, t->http_only);

			goto next;
		}

		ok++;

next:
		mget_cookie_free_cookie(&cookie);
		mget_iri_free(&iri);
	}
}

static void test_utils(void)
{
	int it, ndst;
	unsigned char src[1];
	char dst1[3], dst2[3];

	for (ndst = 1; ndst <= 3; ndst++) {
		for (it = 0; it <= 255; it++) {
			src[0] = it;
			mget_memtohex(src, 1, dst1, ndst);
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
	MGET_VECTOR
		*v = mget_vector_create(2, -2, (int(*)(const void *, const void *))compare_txt);
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
		mget_vector_insert_sorted(v, txt[it], sizeof(struct ENTRY));
	}

	for (it = 0; it < countof(txt); it++) {
		struct ENTRY *e = mget_vector_get(v, it);
		if (!strcmp(e->txt,txt_sorted[it].txt))
			ok++;
		else
			failed++;
	}

	mget_vector_free(&v);
}

// this hash function generates collisions and reduces the map to a simple list.
// O(1) insertion, but O(n) search and removal
static unsigned int hash_txt(G_GNUC_MGET_UNUSED const char *key)
{
	return 0;
}

static void test_stringmap(void)
{
	MGET_STRINGMAP *h;
	char key[128], value[128], *val;
	int run, it, valuesize;

	// the initial size of 16 forces the internal reshashing function to be called twice

	for (run = 0; run < 2; run++) {
		if (run == 0) {
			h = mget_stringmap_create(16);
		} else {
			mget_stringmap_clear(h);
			mget_stringmap_sethashfunc(h, hash_txt);
		}

		for (it = 0; it < 26; it++) {
			sprintf(key, "http://www.example.com/subdir/%d.html", it);
			valuesize = sprintf(value, "%d.html", it);
			if (mget_stringmap_put(h, key, value, valuesize + 1)) {
				failed++;
				info_printf("stringmap_put(%s) returns unexpected old value\n", key);
			} else ok++;
		}

		if ((it = mget_stringmap_size(h)) != 26) {
			failed++;
			info_printf("stringmap_size() returned %d (expected %d)\n", it, 26);
		} else ok++;

		// now, look up every single entry
		for (it = 0; it < 26; it++) {
			sprintf(key, "http://www.example.com/subdir/%d.html", it);
			sprintf(value, "%d.html", it);
			if (!(val = mget_stringmap_get(h, key))) {
				failed++;
				info_printf("stringmap_get(%s) didn't find entry\n", key);
			} else if (strcmp(val, value)) {
				failed++;
				info_printf("stringmap_get(%s) found '%s' (expected '%s')\n", key, val, value);
			} else ok++;
		}

		mget_stringmap_clear(h);

		if ((it = mget_stringmap_size(h)) != 0) {
			failed++;
			info_printf("stringmap_size() returned %d (expected 0)\n", it);
		} else ok++;

		for (it = 0; it < 26; it++) {
			sprintf(key, "http://www.example.com/subdir/%d.html", it);
			valuesize = sprintf(value, "%d.html", it);
			if (mget_stringmap_put(h, key, value, valuesize + 1)) {
				failed++;
				info_printf("stringmap_put(%s) returns unexpected old value\n", key);
			} else ok++;
		}

		if ((it = mget_stringmap_size(h)) != 26) {
			failed++;
			info_printf("stringmap_size() returned %d (expected %d)\n", it, 26);
		} else ok++;

		// now, remove every single entry
		for (it = 0; it < 26; it++) {
			sprintf(key, "http://www.example.com/subdir/%d.html", it);
			sprintf(value, "%d.html", it);
			mget_stringmap_remove(h, key);
		}

		if ((it = mget_stringmap_size(h)) != 0) {
			failed++;
			info_printf("stringmap_size() returned %d (expected 0)\n", it);
		} else ok++;

		for (it = 0; it < 26; it++) {
			sprintf(key, "http://www.example.com/subdir/%d.html", it);
			valuesize = sprintf(value, "%d.html", it);
			if (mget_stringmap_put(h, key, value, valuesize + 1)) {
				failed++;
				info_printf("stringmap_put(%s) returns unexpected old value\n", key);
			} else ok++;
		}

		if ((it = mget_stringmap_size(h)) != 26) {
			failed++;
			info_printf("stringmap_size() returned %d (expected %d)\n", it, 26);
		} else ok++;
	}

	// testing alloc/free in stringmap/hashmap
	mget_stringmap_clear(h);
	mget_stringmap_put(h, "thekey", NULL, 0) ? failed++ : ok++;
	mget_stringmap_put(h, "thekey", NULL, 0) ? ok++ : failed++;
	mget_stringmap_put(h, "thekey", "thevalue", 9) ? ok++ : failed++;
	mget_stringmap_put(h, "thekey", "thevalue", 9) ? ok++ : failed++;
	mget_stringmap_put(h, "thekey", NULL, 0) ? ok++ : failed++;

	// testing key/value identity alloc/free in stringmap/hashmap
	mget_stringmap_clear(h);
	mget_stringmap_put(h, "thekey", NULL, 0) ? failed++ : ok++;
	mget_stringmap_put(h, "thekey", NULL, 0) ? ok++ : failed++;
	mget_stringmap_put(h, "thekey", "thevalue", 9) ? ok++ : failed++;
	mget_stringmap_put(h, "thekey", NULL, 0) ? ok++ : failed++;

	mget_stringmap_free(&h);

	MGET_HTTP_CHALLENGE challenge;
	http_parse_challenge("Basic realm=\"test realm\"", &challenge);
	http_free_challenge(&challenge);

	MGET_VECTOR *challenges;
	challenges = mget_vector_create(2, 2, NULL);
	http_parse_challenge("Basic realm=\"test realm\"", &challenge);
	mget_vector_add(challenges, &challenge, sizeof(challenge));
	http_free_challenges(&challenges);

	char *response_text = strdup(
"HTTP/1.1 401 Authorization Required\r\n"\
"Date: Sun, 23 Dec 2012 21:03:45 GMT\r\n"\
"Server: Apache/2.2.22 (Debian)\r\n"\
"WWW-Authenticate: Digest realm=\"therealm\", nonce=\"Ip6MaovRBAA=c4af733c51270698260f5d357724c2cbce20fa3d\", algorithm=MD5, domain=\"/prot_digest_md5\", qop=\"auth\"\r\n"\
"Vary: Accept-Encoding\r\n"\
"Content-Length: 476\r\n"\
"Keep-Alive: timeout=5, max=99\r\n"\
"Connection: Keep-Alive\r\n"\
"Content-Type: text/html; charset=iso-8859-1\r\n\r\n");

	MGET_IRI *iri = mget_iri_parse("http://localhost/prot_digest_md5/", NULL);
	MGET_HTTP_REQUEST *req = http_create_request(iri, "GET");
	MGET_HTTP_RESPONSE *resp = http_parse_response_header(response_text);
	http_add_credentials(req, mget_vector_get(resp->challenges, 0), "tim", "123");
//	for (it=0;it<vec_size(req->lines);it++) {
//		info_printf("%s\n", (char *)vec_get(req->lines, it));
//	}
	http_free_response(&resp);
	http_free_request(&req);
	mget_iri_free(&iri);
	xfree(response_text);

// Authorization: Digest username="tim", realm="therealm", nonce="Ip6MaovRBAA=c4af733c51270698260f5d357724c2cbce20fa3d", uri="/prot_digest_md5/", response="a99e2012d507a73dd46eb044d3f4641c", qop=auth, nc=00000001, cnonce="3d20faa1"

}

int main(int argc, const char * const *argv)
{
	init(argc, argv); // allows us to test with options (e.g. with --debug)

	srand(time(NULL));

	// testing basic library functionality
	test_buffer();
	test_buffer_printf();
	test_utils();
	test_vector();
	test_stringmap();

	if (failed) {
		info_printf("ERROR: %d out of %d basic tests failed\n", failed, ok + failed);
		info_printf("This may completely break Mget functionality !!!\n");
		return 1;
	}

	test_iri_parse();
	test_iri_relative_to_absolute();
	test_iri_compare();
	test_parser();

	test_cookies();
	mget_cookie_free_public_suffixes();
	mget_cookie_free_cookies();

	selftest_options() ? failed++ : ok++;

	deinit(); // free resources allocated by init()

	if (failed) {
		info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}

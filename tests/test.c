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
#include <string.h>
#include <dirent.h>

#include "../utils.h"
#include "../options.h"
#include "../css.h"
#include "../xml.h"
#include "../iri.h"
#include "../log.h"

static int
	ok,
	failed;

// strcmp, but allows NULL arguments

static int null_strcmp(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strcmp(s1, s2);
	}
}

static void test_iri_parse(void)
{

	static const struct iri_test_data {
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
		{ "//example.com/thepath", NULL, NULL, NULL, NULL, "example.com", NULL, "thepath", NULL, NULL},
		{ "///thepath", NULL, NULL, NULL, NULL, NULL, NULL, "thepath", NULL, NULL},
		{ "example.com", NULL, NULL, NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "http://example.com", NULL, "http", NULL, NULL, "example.com", NULL, NULL, NULL, NULL},
		{ "http://example.com:80", NULL, "http", NULL, NULL, "example.com", "80", NULL, NULL, NULL},
		{ "http://example.com:80/index.html", NULL, "http", NULL, NULL, "example.com", "80", "index.html", NULL, NULL},
		{ "http://example.com:80/index.html?query#frag", NULL, "http", NULL, NULL, "example.com", "80", "index.html", "query", "frag"},
		{ "http://example.com:80/index.html?#", NULL, "http", NULL, NULL, "example.com", "80", "index.html", "", ""},
		{ "碼標準萬國碼.com", NULL, NULL, NULL, NULL, "碼標準萬國碼.com", NULL, NULL, NULL, NULL},
		//		{ "ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm", NULL,"ftp",NULL,NULL,"cnn.example.com",NULL,NULL,"story=breaking_news@10.0.0.1/top_story.htm",NULL }
		{ "ftp://cnn.example.com?story=breaking_news@10.0.0.1/top_story.htm", NULL, "ftp", NULL, NULL, "cnn.example.com", NULL, NULL, "story=breaking_news@10.0.0.1/top_story.htm", NULL}
	};
	unsigned int it;

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
			printf("IRI test #%d failed:\n", it + 1);
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

static void css_dump(UNUSED void *user_ctx, const char *url, size_t len)
{
	info_printf("*** %d '%.*s'\n", len, len, url);
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
				printf("parsing %s\n", fname);
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

	printf("%d XML, %d HTML and %d CSS files parsed\n", xml, html, css);
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
				printf("buffer_to_hex failed: '%s' instead of '%s' (ndst=%d)\n", dst1, dst2, ndst);
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

int main(void)
{
	config.debug = 1;

	test_iri_parse();
	test_parser();
	test_utils();

	if (failed) {
		printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	} else {
		printf("Summary: All %d tests passed\n", ok + failed);
		return 0;
	}
}

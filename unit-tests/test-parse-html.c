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
 * 16.08.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <c-ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#include <wget.h>
#include "../libwget/private.h"
#include "../src/wget_options.h"

static int
	ok,
	failed;

static const char *test_data[] ={
	"<!doctype html>\n"\
	"<!--[if lt IE 7 ]> <html class=\"no-js ie6\" lang=\"en\"> <![endif]-->\n"\
	"<!--[if (gte IE 9)|!(IE)]><!--> <html class=\"no-js\"> <!--<![endif]-->\n"\
	"<head>\n"\
   "  <meta charset=\"utf-8\">\n"\
	"  <script>window.jQuery || document.write(\"<script src='/common/inc/js/jquery-1.5.1.min.js'><\\/script>\")</script>\n"\
	"  <script src=\"/common/inc/js/core.js?v=1\"></script>\n"\
	"</head>\n"\
	"<body>\n"\
	"  <ul>\n"\
	"    <li><a href=\"/solutions/platform.html#server\">Server</a></li>\n"\
	"    <li><a href=\"/solutions/platform.html#desktop\">Desktop</a></li>\n"\
	"  </ul>\n"\
	"</body>\n"\
	"</html>\n"
};

static void html_dump(void *user_ctx, int flags, const char *dir WGET_GCC_UNUSED, const char *attr, const char *val, size_t len, size_t pos)
{
//	info_printf("\n%02X %s %s '%.*s' %zd %zd\n", flags, dir, attr, (int) len, val, len, pos);
	if ((flags & XML_FLG_ATTRIBUTE) && val) {
		// info_printf("%02X %s %s '%.*s' %zd %zd\n", flags, dir, attr, (int) len, val, len, pos);

		// very simplified
		// see http://stackoverflow.com/questions/2725156/complete-list-of-html-tag-attributes-which-have-a-url-value
		switch (c_tolower(*attr)) {
		case 'h':
			if (wget_strcasecmp_ascii(attr, "href"))
				return;
			break;
		case 's':
			if (wget_strcasecmp_ascii(attr, "src"))
				return;
			break;
		default:
			return;
		}

		// check if len and pos matches
		const char *doc = (const char *)user_ctx;

		if (memcmp(doc + pos, val, len)) {
			failed++;
			error_printf_exit("Not found: '%.*s' expected at pos %zu with length %zu\n", (int) len, val, pos, len);
		} else
			ok++;
	}

/*
	if (flags & XML_FLG_BEGIN) {
		const char *p = *dir == '/' ? strrchr(dir, '/') : dir;
		if (p) {
			if (*dir == '/') p++;
			if (flags == (XML_FLG_BEGIN | XML_FLG_END)) {
				info_printf("<%s/>", p);
				return;
			}
			info_printf("<%s", p);
		}
	}
	if (flags & XML_FLG_ATTRIBUTE) {
		if (val)
			info_printf(" %s=\"%.*s\"", attr, (int) len, val);
		else
			info_printf(" %s", attr); // HTML bareword attribute
	}
	if (flags & XML_FLG_CLOSE) {
		info_printf(">");
	}
	if (flags & XML_FLG_CONTENT) {
		info_printf("%.*s", (int) len, val);
	}
	if (flags & XML_FLG_END) {
		const char *p = *dir == '/' ? strrchr(dir, '/') : dir;
		if (p) {
			if (*dir == '/') p++;
			info_printf("</%s>", p);
		}
	}

	if (flags == XML_FLG_COMMENT)
		info_printf("<!--%.*s-->", (int) len, val);
	else if (flags == XML_FLG_PROCESSING)
		info_printf("<?%.*s?>", (int) len, val);
	else if (flags == XML_FLG_SPECIAL)
		info_printf("<!%.*s>", (int) len, val);
*/
}

static void test_parse_buffer(void)
{
	unsigned it;

	for (it = 0; it < countof(test_data); it++) {
		wget_html_parse_buffer(test_data[it], html_dump, (void *)test_data[it], 0);
	}
}

static void test_parse_files(void)
{
	DIR *dirp;
	struct dirent *dp;
	const char *ext;
	int xml = 0, html = 0, css = 0, type;

	// test the XML / HTML parser, you should start the test with valgrind
	// to detect memory faults
	if ((dirp = opendir(SRCDIR "/files")) != NULL) {
		while ((dp = readdir(dirp)) != NULL) {
			if (*dp->d_name == '.') continue;
			if ((ext = strrchr(dp->d_name, '.'))) {
				if (!wget_strcasecmp_ascii(ext, ".xml"))
					type = 1;
				else if (!wget_strcasecmp_ascii(ext, ".html"))
					type = 2;
				else
					continue;

				char *fname = wget_aprintf("%s/files/%s", SRCDIR, dp->d_name);
				info_printf("parsing %s\n", fname);

				char *data;

				if ((data = wget_read_file(fname, NULL))) {
					if (type == 1) {
						wget_xml_parse_buffer(data, html_dump, data, 0);
						xml++;
					} else {
						wget_html_parse_buffer(data, html_dump, data, 0);
						html++;
					}

					xfree(data);
				}

				xfree(fname);
			}
		}
		closedir(dirp);
	}

	info_printf("%d XML, %d HTML and %d CSS files parsed\n", xml, html, css);
}

int main(int argc, const char **argv)
{
	if (init(argc, argv) < 0) // allows us to test with options (e.g. with --debug)
		return -1;
	test_parse_buffer();
	test_parse_files();

	deinit(); // free resources allocated by init()

	if (failed) {
		info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}

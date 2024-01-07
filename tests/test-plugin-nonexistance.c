/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget
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
 * along with Wget  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Testing Wget plugin behavior with non-existent plugins
 *
 */
#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include <unistd.h> // access()
#include "libtest.h"
#include "plugin_tests.h"

static const char *mainpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    <a href=\"http://localhost:{{port}}/secondpage.html\">second page</a>.\n\
    <a href=\"http://localhost:{{port}}/thirdpage.html\">third page</a>.\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *subpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Some text\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *errorpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Error.\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *rot13_mainpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    second page: rot13(uggc://ybpnyubfg:{{port}}/frpbaqcntr.ugzy)\n\
    third page: rot13(uggc://ybpnyubfg:{{port}}/guveqcntr.ugzy)\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *rot13_mainpage_mixed = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    second page: rot13(uggc://ybpnyubfg:{{port}}/frpbaqcntr.ugzy)\n\
    third page: rot13(uggc://ybpnyubfg:{{port}}/guveqcntr.ugzy)\n\
    <a href=\"http://localhost:{{port}}/forthpage.html\">forth page</a>.\n\
  </p>\n\
</body>\n\
</html>\n";

static const char data[129] = "\
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n\
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n";

int main(void)
{
#ifdef LARGEFILE
	char *largedata = wget_malloc(LARGEFILE + 1);
	memset(largedata, 'x', LARGEFILE);
	largedata[LARGEFILE] = 0;
#endif
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body = mainpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body = subpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/thirdpage.html",
			.code = "200 Dontcare",
			.body = subpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/forthpage.html",
			.code = "200 Dontcare",
			.body = subpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/rot13_index.html",
			.code = "200 Dontcare",
			.body = rot13_mainpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/rot13_index_mixed.html",
			.code = "200 Dontcare",
			.body = rot13_mainpage_mixed,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/data.txt",
			.code = "200 Dontcare",
			.body = data,
			.headers = {
				"Content-Type: text/plain",
			},
		},
#ifdef LARGEFILE
		{	.name = "/large.txt",
			.code = "200 Dontcare",
			.body = largedata,
			.headers = {
				"Content-Type: text/plain",
			},
		},
#endif
		{	.name = "/error.html",
			.code = "404 Not exist",
			.body = errorpage,
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	if (access(".libs/libpluginname.so", R_OK) != 0
		&& access(".libs/libpluginname.dll", R_OK) != 0
		&& access(".libs/cygpluginname.dll", R_OK) != 0)
		exit(WGET_TEST_EXIT_SKIP); // likely a static build

	wget_test_start_server(
			WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
			WGET_TEST_FEATURE_MHD,
			WGET_TEST_FEATURE_PLUGIN,
			0);

	// Check behavior for nonexistent plugins
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR " --plugin=nonexistent",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 2,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("nonexistent"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 2,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	setenv_rpl("WGET2_PLUGINS", LOCAL_NAME("nonexistent") , 1);
	wget_test(
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 2,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	unsetenv_rpl("WGET2_PLUGINS");

	// Check behavior for nonexistent search directories
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR "/nonexistent," OBJECT_DIR " --plugin=pluginname",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR "/nonexistent," OBJECT_DIR " --list-plugins",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);

}

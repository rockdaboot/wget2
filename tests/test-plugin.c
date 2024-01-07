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
 * Testing Wget plugin support
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include <unistd.h> // access()
#include "libtest.h"
#include "plugin_tests.h"

// #define LARGEFILE (11 << 20)

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

	// Check whether --plugin= works
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR " --plugin=pluginname",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);

	// Check whether --local-plugin= works
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginname"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);

	// Check whether WGET2_PLUGINS works
	setenv_rpl("WGET2_PLUGIN_DIRS", OBJECT_DIR, 1);
	setenv_rpl("WGET2_PLUGINS", "pluginname", 1);
	wget_test(
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);
	unsetenv_rpl("WGET2_PLUGIN_DIRS");
	unsetenv_rpl("WGET2_PLUGINS");
	setenv_rpl("WGET2_PLUGINS", LOCAL_NAME("pluginname") , 1);
	wget_test(
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);
	unsetenv_rpl("WGET2_PLUGINS");

	// Check that --list-plugins doesn't continue
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR " --list-plugins",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// Check whether wget_plugin_register_finalizer works properly
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginexit"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "exit-status.txt", "exit(0)\n" },
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginexit"),
		WGET_TEST_REQUEST_URL, "nonexistent.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "exit-status.txt", "exit(8)\n" },
			{	NULL } },
		0);

	// Check if option forwarding works for options with no value
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.y",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "options.txt", "y\n" },
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.y "
			"--plugin-opt=pluginoption.beta",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "options.txt", "y\nbeta\n" },
			{	NULL } },
		0);

	// Check if option forwarding works with options with values
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.z= "
			"--plugin-opt=pluginoption.z=value1 --plugin-opt=pluginoption.gamma=value2",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "options.txt", "z=\nz=value1\ngamma=value2\n" },
			{	NULL } },
		0);

	// Check for correct functioning of --help option
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-help",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.help",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.help=arg",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 2,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// Check whether overriding default wget2's post processing works
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginapi") " --recursive --no-host-directories"
			" --plugin-opt=pluginapi.parse-rot13 --plugin-opt=pluginapi.test-pp"
			" --plugin-opt=pluginapi.only-rot13",
		WGET_TEST_REQUEST_URL, "rot13_index_mixed.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "rot13_index_mixed.html", urls[5].body },
			{ "secondpage.html", urls[1].body },
			{ "thirdpage.html", urls[2].body },
			{ "files_processed.txt", "rot13_index_mixed.html\nsecondpage.html\nthirdpage.html\n" },
			{	NULL } },
		0);

	// Check whether priority based database selection works correctly
	wget_test(
		WGET_TEST_OPTIONS,
			"--hpkp --hpkp-file=hpkp.db "
			"--hsts --hsts-file=hsts.db "
			"--ocsp --ocsp-file=ocsp.db "
			"--local-plugin=" LOCAL_NAME("plugindb"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "hpkp.db", "# HPKP 1.0 file\nexample.com 1491338542 1 1488746542\n*sha256 8dNiZZueNzmyaf3pTkXxDgOzLkjKvI+Nza0ACF5IDwg=" },
			{ "hsts.db", "#HSTS 1.0 file\nexample.com 443 1 1499023633 63072000" },
			{ "ocsp.db", "#OCSP 1.0 file\n" },
			{ NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "hpkp.db", NULL },
			{ "hsts.db", NULL },
			{ "ocsp.db", NULL },
			{ NULL } },
		0);

	exit(EXIT_SUCCESS);
}

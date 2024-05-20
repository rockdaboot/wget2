/*
 * Copyright (c) 2013 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Testing Wget
 *
 * Changelog
 * 10.03.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

static const char *mainpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Some text and a link to a <a href=\"http://localhost:{{port}}/secondpage.html\">second page</a>.\n\
    Also, a <a href=\"http://localhost:{{port}}/nonexistent\">broken link</a>.\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *secondpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Some text and a link to a <a href=\"http://localhost:{{port}}/thirdpage.html\">third page</a>.\n\
    Also, a <a href=\"http://localhost:{{port}}/nonexistent\">broken link</a>.\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *thirdpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Some text and a link to a <a href=\"http://localhost:{{port}}/dummy.txt\">dummy text</a>.\n\
    Also, a <a href=\"http://localhost:{{port}}/againnonexistent\">broken link</a>.\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *dummypage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Don't care.\n\
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

int main(void)
{
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
			.body = secondpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/thirdpage.html",
			.code = "200 Dontcare",
			.body = thirdpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/dummy.txt",
			.code = "200 Dontcare",
			.body = "Don't care.",
			.headers = {
				"Content-Type: text/plain",
			},
		},
		{	.name = "/dummy.html",
			.code = "200 Dontcare",
			.body = dummypage,
			.headers = {
				"Content-Type: text/plain",
            "Content-Disposition: attachment; filename=\"filename.html\"",
			}
		},
		{	.name = "/dummy2.html",
			.code = "200 Dontcare",
			.body = dummypage,
			.headers = {
				"Content-Type: text/plain",
            "Content-Disposition: attachment; filename*=UTF-8''%66ile_fran%c3%A7ais.html",
			}
		},
		{	.name = "/error.html",
			.code = "404 Not exist",
			.body = errorpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/error503.html",
			.code = "503 Service Unavailable",
			.body = errorpage,
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// some tests are not working on file systems that mangle filenames to lower- or uppercase
	int fs_flags = wget_test_check_file_system();

	// test-noop
	wget_test(
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{	NULL } },
		0);

	// test-nonexistent-quiet
	wget_test(
		WGET_TEST_OPTIONS, "--quiet",
		WGET_TEST_REQUEST_URL, "nonexistent",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		0);

	// test-stdouterr
#ifdef __linux__
	if (access("/dev/full", W_OK)) {
		// TODO: Find better file to use for other operating systems.
		wget_test(
			WGET_TEST_OPTIONS, "-c -O /dev/full",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 3,
			0);
	}
#endif

	// test--spider
	wget_test(
		WGET_TEST_OPTIONS, "--spider",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		0);

	// test--spider-fail
	wget_test(
		WGET_TEST_OPTIONS, "--spider",
		WGET_TEST_REQUEST_URL, "nonexistent",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		0);

	// test--spider-r--no-content-disposition-trivial
	wget_test(
		WGET_TEST_OPTIONS, "--spider -r --no-content-disposition",
		WGET_TEST_REQUEST_URL, "",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		0);

	// test--no-content-disposition-trivial
	wget_test(
		WGET_TEST_OPTIONS, "--no-content-disposition",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{	NULL } },
		0);

	urls[1].headers[1] = "Content-Disposition: attachment; filename=\"filename.html\"";

	// test--no-content-disposition
	wget_test(
		WGET_TEST_OPTIONS, "--no-content-disposition",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{	NULL } },
		0);

	// test--spider-r--no-content-disposition
	wget_test(
		WGET_TEST_OPTIONS, "--spider -r --no-content-disposition",
		WGET_TEST_REQUEST_URL, "",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		0);

	urls[1].headers[1] = NULL;

	// test--HTTP-content-disposition
	wget_test(
		WGET_TEST_OPTIONS, "-e contentdisposition=on",
		WGET_TEST_REQUEST_URL, "dummy.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"filename.html", dummypage },
			{	NULL } },
		0);

	// test--HTTP-content-disposition-1
	wget_test(
		WGET_TEST_OPTIONS, "-e contentdisposition=on",
		WGET_TEST_REQUEST_URL, "dummy.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"filename.html", "dontcare" },
			{	"filename.html.1", "dontcare" },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"filename.html", "dontcare" },
			{	"filename.html.1", "dontcare" },
			{	"filename.html.2", dummypage },
			{	NULL } },
		0);

	// test--HTTP-content-disposition-2
	wget_test(
		WGET_TEST_OPTIONS, "--no-content-disposition",
		WGET_TEST_REQUEST_URL, "dummy.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"filename.html", "dontcare" },
			{	"filename.html.1", "dontcare" },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"filename.html", "dontcare" },
			{	"filename.html.1", "dontcare" },
			{	"dummy.html", dummypage },
			{	NULL } },
		0);

	// test--HTTP-content-disposition-RFC6266
#define ccedilla_u8 "\xC3\xA7"
	wget_test(
		WGET_TEST_OPTIONS, "-e contentdisposition=on --local-encoding=utf-8",
		WGET_TEST_REQUEST_URL, "dummy2.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"filename.html", "dontcare" },
			{	"filename.html.1", "dontcare" },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"filename.html", "dontcare" },
			{	"filename.html.1", "dontcare" },
			{	"file_fran" ccedilla_u8 "ais.html", dummypage },
			{	NULL } },
		0);

	urls[1].headers[1] = "Content-Disposition: attachment; filename=\"filename.html\"";

	// test-O--no-content-disposition
	wget_test(
		WGET_TEST_OPTIONS, "-O out --no-content-disposition",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"out", urls[3].body },
			{	NULL } },
		0);

	// test-O-HTTP-content-disposition
	wget_test(
		WGET_TEST_OPTIONS, "-O out",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"out", urls[3].body },
			{	NULL } },
		0);


	urls[3].headers[1] = NULL;

	// test-O-nc
	wget_test(
		WGET_TEST_OPTIONS, "-nc -O out",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"out", urls[3].body },
			{	NULL } },
		0);

	// test-O-nonexisting
	wget_test(
		WGET_TEST_OPTIONS, "-O out",
		WGET_TEST_REQUEST_URL, "nonexistent",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			// {	"out", "" }, // Wget would create an empty file here, but Wget not
			{	NULL } },
		0);

	// test-O
	wget_test(
		WGET_TEST_OPTIONS, "-O out",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"out", urls[3].body },
			{	NULL } },
		0);

	if ((fs_flags & WGET_TEST_FS_CASEMATTERS) == 0) {
		urls[3].name="/DuMmy.Txt";

		// test-restrict-lowercase
		wget_test(
			WGET_TEST_OPTIONS, "--restrict-file-names=lowercase",
			WGET_TEST_REQUEST_URL, "DuMmy.Txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", urls[3].body },
				{	NULL } },
			0);

		// test-restrict-uppercase
		wget_test(
			WGET_TEST_OPTIONS, "--restrict-file-names=uppercase",
			WGET_TEST_REQUEST_URL, "DuMmy.Txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"DUMMY.TXT", urls[3].body },
				{	NULL } },
			0);

		urls[3].name="/dummy.txt";
	}

	// test-c-full
	wget_test(
		WGET_TEST_OPTIONS, "-c",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	{
		// server sends same length content with slightly different content
		char *partial = wget_strmemdup(urls[3].body, strlen(urls[3].body)-2);

		// test-c-partial
		wget_test(
			WGET_TEST_OPTIONS, "-c",
			WGET_TEST_REQUEST_URL, "dummy.txt",
//			WGET_TEST_KEEP_TMPFILES, 1,
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", partial },
				{	NULL } },
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", urls[3].body },
				{	NULL } },
			0);

		wget_test(
			WGET_TEST_OPTIONS, "--header Range:bytes=9-",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", partial },
				{	NULL } },
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", urls[3].body },
				{	NULL } },
			0);

		wget_xfree(partial);
	}


/*
 * this test needs a broken server ... I don't have one right now.
	{
		// server sends same length content with slightly different content
		char *partial = wget_strmemdup(urls[3].body, strlen(urls[3].body)-2);
		const char *old_body = urls[3].body;
		urls[3].body = "";

		// test-c-shorter
		wget_test(
			WGET_TEST_OPTIONS, "-c",
			WGET_TEST_REQUEST_URL, "dummy.txt",
//			WGET_TEST_KEEP_TMPFILES, 1,
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", partial },
				{	NULL } },
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", urls[3].body },
				{	NULL } },
			0);

		urls[3].body = old_body;
		wget_xfree(partial);
	}
*/
	// test-c
	wget_test(
		WGET_TEST_OPTIONS, "-c",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test-O--continue-existing
	wget_test(
		WGET_TEST_OPTIONS, "-O newindex.html -c",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ "newindex.html", urls[0].body },
			{	NULL } },
		0);

	// test -c with existing empty file
	wget_test(
		WGET_TEST_OPTIONS, "-c",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, "" },
			{	NULL } },
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	// test -c with existing complete file
	wget_test(
		WGET_TEST_OPTIONS, "-c",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	// test --chunk-size, new file
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=3",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test --chunk-size with --progress, new file
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=3 --progress=bar",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test --chunk-size, new file, without Content-Length header
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=3",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_SERVER_SEND_CONTENT_LENGTH, 0, // server does not send Content-Length
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test --chunk-size with --progress, new file, without Content-Length header
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=3 --progress=bar",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_SERVER_SEND_CONTENT_LENGTH, 0, // server does not send Content-Length
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test --chunk-size, new file, with chunk size > Content-Length
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=1000",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test --chunk-size with --progress, new file, with chunk size > Content-Length
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=1000 --progress=bar",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test -c --chunk-size, new file
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=3 -c",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test -c --chunk-size with --progress, new file
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=3 -c --progress=bar",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		// no existing file
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test -c --chunk-size, existing file
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=3 -c",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "dummy.txt",  urls[3].body },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test -c --chunk-size with --progress, existing file
	wget_test(
		WGET_TEST_OPTIONS, "--chunk-size=3 -c --progress=bar",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "dummy.txt",  urls[3].body },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test different --progress options to be accepted
	wget_test(
		WGET_TEST_OPTIONS, "--progress=none --progress=bar --progress=bar:force --progress=bar:noscroll:force --progress=dot --progress=dot:giga",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[3].body },
			{	NULL } },
		0);

	// test--https-only
	wget_test(
		WGET_TEST_OPTIONS, "--https-only -r -nH",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"index.html", urls[0].body },
			{	NULL } },
		0);

	// test --content-on-error
	wget_test(
		WGET_TEST_OPTIONS, "--content-on-error",
		WGET_TEST_REQUEST_URL, "error.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// test not saving file on error
	wget_test(
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, "error.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// test response code 503
	wget_test(
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, "error503.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}

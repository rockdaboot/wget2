/*
 * Copyright (c) 2026 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<!DOCTYPE html>\n"
				"<html>\n"
				"<head>\n"
				"    <link rel=\"stylesheet\" href=\"style.css\">\n"
				"</head>\n"
				"<body>\n"
				"    Are background images rewritten?\n"
				"</body>\n"
				"</html>\n",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/style.css",
			.code = "200 Dontcare",
			.body =
				"@import url(\"http://localhost:{{port}}/style2.css\");\n"
				"\n"
				"body {\n"
				"    background-image: url(http://localhost:{{port}}/image.png);\n"
				"}\n",
			.headers = {
				"Content-Type: text/css",
			}
		},
		{	.name = "/style2.css",
			.code = "200 Dontcare",
			.body = "/* empty */\n",
			.headers = {
				"Content-Type: text/css",
			}
		},
		{	.name = "/image.png",
			.code = "200 Dontcare",
			.body = "PNG data",
			.headers = {
				"Content-Type: image/png",
			}
		}
	};

	const char *expected_style_css =
		"@import url(\"style2.css\");\n"
		"\n"
		"body {\n"
		"    background-image: url(image.png);\n"
		"}\n";

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// check that CSS urls are rewritten to local paths
	wget_test(
		WGET_TEST_OPTIONS, "--page-requisites --convert-links -nH",
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },   // index.html
			{ urls[1].name + 1, expected_style_css }, // style.css (converted)
			{ urls[2].name + 1, urls[2].body },   // style2.css
			{ urls[3].name + 1, urls[3].body },   // image.png
			{ NULL } },
		0);

	exit(EXIT_SUCCESS);
}

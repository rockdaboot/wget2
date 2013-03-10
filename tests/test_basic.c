/*
 * Copyright(c) 2013 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Testing Mget
 *
 * Changelog
 * 10.03.2013  Tim Ruehsen  created
 *
 */

#include "libtest.h"

static const char *body = "\
<html>\n\
<head>\n\
  <title>The Title</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Some text\n\
  </p>\n\
</body>\n\
</html>\n";

int main(int argc G_GNUC_MGET_UNUSED, const char *const *argv G_GNUC_MGET_UNUSED)
{
	// function won't come back if an error occurs
	mget_test_start_http_server(
		MGET_TEST_RESPONSE_BODY, body,
		MGET_TEST_RESPONSE_HEADER, "Content-Type: text/html",
		0);

	// function won't come back if an error occurs
	mget_test(
		MGET_TEST_NAME, "Basic HTTP Get",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILE, "index.html",
		MGET_TEST_EXPECTED_FILE_CONTENT, body,
		0);

	return 0;
}

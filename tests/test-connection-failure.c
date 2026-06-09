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
 *
 *
 * Testing exit code on connection failure
 *
 * Changelog
 * 08.06.2026  Created
 *
 */

#include <config.h>

#include <stdlib.h>
#include "libtest.h"

int main(void)
{
	// Server that rejects all connections - simulates connection refused/failure
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, NULL, 0,
		WGET_TEST_HTTP_REJECT_CONNECTIONS,
		WGET_TEST_FEATURE_MHD,
		0);

	// With --tries=2 and a server that rejects connections, wget2 should exit
	// with code 4 (EXIT_STATUS_NETWORK) after the host is blocked.
	// Without the fix, wget2 would exit with code 0 despite failures.
	wget_test(
		WGET_TEST_OPTIONS, "--tries=2 --waitretry=1",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 4,
		0);

	exit(EXIT_SUCCESS);
}

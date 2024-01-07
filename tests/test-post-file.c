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
 * 15.07.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	// functions won't come back if an error occurs
	wget_test_start_server(WGET_TEST_FEATURE_MHD, 0);

	// test-i
	wget_test(
		WGET_TEST_OPTIONS, "--post-file=nofile",
		WGET_TEST_REQUEST_URL, "",
		WGET_TEST_EXPECTED_ERROR_CODE, 3, // fails with older Wget (<= 1.14)
		0);

	exit(EXIT_SUCCESS);
}

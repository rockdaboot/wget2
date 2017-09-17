/*
 * Copyright(c) 2013 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Testing Wget
 *
 * Changelog
 * 08.07.2015  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "info.txt",
			.body = "Dummy file content"
		},
		{	.name = ".listing",
			.body =
"drwxr-xr-x   9 ftp      ftp          4096 Aug 14  2013 .\r\n"
"drwxr-xr-x   9 ftp      ftp          4096 Aug 14  2013 ..\r\n"
"lrw-r--r--   1 ftp      ftp            16 Jan 12  2013 dir2 -> dir1\r\n"
"drwxr-xr-x   8 ftp      ftp          4096 Jul  8 15:37 dir1\r\n"
"-rw-r--r--   1 ftp      ftp           245 Jul  1  2013 info.txt\r\n"
		},
	};
	wget_test_ftp_io_t io[]={
		{	.in  = "USER anonymous",
			.out = "331 Anonymous login ok"
		},
		{	.in  = "PASS -wget@",
			.out = "230- Hello\r\n and good night\r\n\r\n230 Access granted"
		},
		{	.in  = "SYST",
			.out = "215 UNIX Type: L8"
		},
		{	.in  = "PWD",
			.out = "257 \"/\" is the current directory"
		},
		{	.in  = "TYPE I",
			.out = "200 Type set to I"
		},
		{	.in  = "PASV",
			.out = "227 Entering Passive Mode {{pasvdata}}."
		},
		{	.in  = "EPSV 2",
			.out = "229 Entering Passive Mode {{pasvdata}}."
		},
		{	.in  = "LIST -a",
			.out = "150 Opening BINARY mode data connection for file list",
			.send_url = &urls[1]
		},
		{	.in  = "RETR info.txt",
			.out = "150 Opening BINARY mode data connection",
			.send_url = &urls[0]
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FTP_IO_UNORDERED, &io, countof(io),
		WGET_TEST_FEATURE_FTP,
		0);

	char options[128];

	// without -O/dev/null Wget generates HTML output from the listing
	snprintf(options, sizeof(options),
		"-d --no-remove-listing -O/dev/null ftp://localhost:%d",
		wget_test_get_ftp_server_port());

	// test downloading the top directory content
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_EXECUTABLE, "wget",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[1].name, urls[1].body },
			{	NULL } },
		0);

	// without -O/dev/null Wget generates HTML output from the listing
	snprintf(options, sizeof(options),
		"-d ftp://localhost:%d/info.txt",
		wget_test_get_ftp_server_port());

	// test downloading a file
	wget_test(
//		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_EXECUTABLE, "wget",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name, urls[0].body },
			{	NULL } },
		0);

	exit(0);
}

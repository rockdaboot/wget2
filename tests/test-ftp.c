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
 * 08.07.2015  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	mget_test_url_t urls[]={
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
	mget_test_ftp_io_t io[]={
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
	mget_test_start_server(
		MGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		MGET_TEST_FTP_IO_UNORDERED, &io, countof(io),
		0);

	char options[128];

	// without -O/dev/null Wget generates HTML output from the listing
	snprintf(options, sizeof(options),
		"-d --no-remove-listing -O/dev/null ftp://localhost:%d",
		mget_test_get_ftp_server_port());

	// test downloading the top directory content
	mget_test(
//		MGET_TEST_KEEP_TMPFILES, 1,
		MGET_TEST_OPTIONS, options,
		MGET_TEST_EXECUTABLE, "wget",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[1].name, urls[1].body },
			{	NULL } },
		0);

	// without -O/dev/null Wget generates HTML output from the listing
	snprintf(options, sizeof(options),
		"-d ftp://localhost:%d/info.txt",
		mget_test_get_ftp_server_port());

	// test downloading a file
	mget_test(
//		MGET_TEST_KEEP_TMPFILES, 1,
		MGET_TEST_OPTIONS, options,
		MGET_TEST_EXECUTABLE, "wget",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name, urls[0].body },
			{	NULL } },
		0);

	exit(0);
}

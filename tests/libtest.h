/*
 * Copyright(c) 2013-2014 Tim Ruehsen
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
 * Test suite function library header
 *
 * Changelog
 * 10.03.2013  Tim Ruehsen  created
 *
 * Test suite function library
 *
 * To create the X.509 stuff, I followed the instructions at
 *   gnutls.org/manual/html_node/gnutls_002dserv-Invocation.html
 *
 */

#ifndef _LIBMGET_LIBTEST_H
#define _LIBMGET_LIBTEST_H

#include <libmget.h>

#ifdef	__cplusplus
extern "C" {
#endif

// defines for mget_test_start_http_server()
#define MGET_TEST_EXPECTED_REQUEST_HEADER 1001
#define MGET_TEST_RESPONSE_URLS 1002
#define MGET_TEST_FTP_IO_UNORDERED 1003
#define MGET_TEST_FTP_IO_ORDERED 1004
#define MGET_TEST_FTP_SERVER_HELLO 1005
#define MGET_TEST_FTPS_IMPLICIT 1006

// defines for mget_test()
#define MGET_TEST_REQUEST_URL 2001
#define MGET_TEST_OPTIONS 2002
#define MGET_TEST_EXPECTED_ERROR_CODE 2003
#define MGET_TEST_EXPECTED_FILES 2004
#define MGET_TEST_EXISTING_FILES 2005
#define MGET_TEST_KEEP_TMPFILES 2006
#define MGET_TEST_REQUEST_URLS 2007
#define MGET_TEST_EXECUTABLE 2008

#define countof(a) (sizeof(a)/sizeof(*(a)))

G_GNUC_MGET_UNUSED static const char *MGET_TEST_SOME_HTML_BODY = "\
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

typedef struct {
	const char *
		name;
	const char *
		content;
	time_t
		timestamp;
} mget_test_file_t;

typedef struct {
	const char *
		name;
	const char *
		code;
	const char *
		body;
	const char *
		headers[10];
	const char *
		request_headers[10];
	time_t
		modified;
	char
		body_alloc; // if body has been allocated internally (and need to be freed on exit)

	// auth fields
	const char *
		auth_method;
	const char *
		auth_username;
	const char *
		auth_password;
} mget_test_url_t;

typedef struct {
	const char *
		in;
	const char *
		out;
	mget_test_url_t *
		send_url;
} mget_test_ftp_io_t;

void mget_test_stop_server(void);
void mget_test_start_server(int first_key, ...);
void mget_test(int first_key, ...);
int mget_test_get_http_server_port(void) G_GNUC_MGET_PURE;
int mget_test_get_https_server_port(void) G_GNUC_MGET_PURE;
int mget_test_get_ftp_server_port(void) G_GNUC_MGET_PURE;
int mget_test_get_ftps_server_port(void) G_GNUC_MGET_PURE;

#if defined(__clang__) || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
#	pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBMGET_LIBTEST_H */

/*
 * Copyright (c) 2013-2014 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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

#ifndef TESTS_LIBTEST_H
#define TESTS_LIBTEST_H

#include <wget.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define WGET_TEST_EXIT_SKIP 77

// defines for wget_test_start_http_server()
#define WGET_TEST_RESPONSE_URLS 1002
#define WGET_TEST_HTTP_ONLY 1003
#define WGET_TEST_HTTPS_ONLY 1004
#define WGET_TEST_HTTP_REJECT_CONNECTIONS 1005
#define WGET_TEST_HTTPS_REJECT_CONNECTIONS 1006
#define WGET_TEST_H2_ONLY 1007
#define WGET_TEST_SKIP_H2 1008
#define WGET_TEST_FEATURE_MHD 1101
#define WGET_TEST_FEATURE_TLS 1102
#define WGET_TEST_FEATURE_IDN 1103
#define WGET_TEST_FEATURE_PLUGIN 1104
#define WGET_TEST_FEATURE_OCSP 1105
#define WGET_TEST_FEATURE_OCSP_STAPLING 1106

// defines for wget_test()
#define WGET_TEST_REQUEST_URL 2001
#define WGET_TEST_OPTIONS 2002
#define WGET_TEST_EXPECTED_ERROR_CODE 2003
#define WGET_TEST_EXPECTED_FILES 2004
#define WGET_TEST_EXISTING_FILES 2005
#define WGET_TEST_KEEP_TMPFILES 2006
#define WGET_TEST_REQUEST_URLS 2007
#define WGET_TEST_EXECUTABLE 2008
#define WGET_TEST_SERVER_SEND_CONTENT_LENGTH 2009
#define WGET_TEST_EXPECTED_ERROR_CODE2 2010
#define WGET_TEST_CLEAN_DIRECTORY 2011

// defines for wget_test_check_file_system()
#define WGET_TEST_FS_CASEMATTERS 3001 // file system is case-sensitive

// for post-handshake authentication
#define WGET_TEST_POST_HANDSHAKE_AUTH 3002

// for OCSP testing
#define WGET_TEST_OCSP_RESP_FILES 3003

typedef enum {
	INTERRUPT_RESPONSE_DISABLED = 0,
	INTERRUPT_RESPONSE_DURING_BODY
} interrupt_response_mode_t;

#define countof(a) (sizeof(a)/sizeof(*(a)))

#define TEST_OPAQUE_STR "11733b200778ce33060f31c9af70a870ba96ddd4"

WGET_GCC_UNUSED static const char *WGET_TEST_SOME_HTML_BODY = "\
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
	char
		restricted_mode;
	size_t
		content_length;
	const char *
		hardlink;
} wget_test_file_t;

typedef struct {
	const char *
		name;
	const char *
		code;
	const char *
		body;
	const char *
		body_original;
	const char *
		headers[10];
	const char *
		headers_original[10];
	const char *
		request_headers[10];
	const char *
		expected_req_headers[10];
	const char *
		unexpected_req_headers[10];
	const char *
		expected_method;
	int64_t
		modified;

	// auth fields
	const char *
		auth_method;
	const char *
		auth_username;
	const char *
		auth_password;
	size_t
		body_len; // The length of the body in bytes. 0 means use strlen(body)

	interrupt_response_mode_t
		interrupt_response_mode;
	size_t
		interrupt_response_after_nbytes;

	bool
		https_only : 1,
		http_only : 1;
} wget_test_url_t;

WGETAPI void wget_test_stop_server(void);
WGETAPI void wget_test_start_server(int first_key, ...);
WGETAPI void wget_test(int first_key, ...);
WGETAPI int wget_test_check_file_system(void);
WGETAPI void wget_test_set_executable(const char *);
WGETAPI int wget_test_get_http_server_port(void) WGET_GCC_PURE;
WGETAPI int wget_test_get_https_server_port(void) WGET_GCC_PURE;
WGETAPI int wget_test_get_ocsp_server_port(void) WGET_GCC_PURE;
WGETAPI int wget_test_get_h2_server_port(void) WGET_GCC_PURE;

#if defined __clang__ || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
#	pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBWGET_LIBTEST_H */

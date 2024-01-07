/*
 * Copyright (c) 2013 Tim Ruehsen
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
 * Example for retrieving and parsing an HTTP URI
 *
 * Changelog
 * 16.01.2013  Tim Ruehsen  created
 *
 * Simple demonstration how to download an URI.
 *
 */

#include <wget.h>

#define COOKIE_SUPPORT

int main(void)
{
	wget_iri *uri;
	wget_http_connection *conn = NULL;
	wget_http_request *req;
	wget_cookie_db *cookies;

	// We want the libwget debug messages be printed to STDERR.
	// From here on, we can call wget_debug_printf, etc.
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);

	// We want the libwget error messages be printed to STDERR.
	// From here on, we can call wget_error_printf, etc.
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);

	// We want the libwget info messages be printed to STDOUT.
	// From here on, we can call wget_info_printf, etc.
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stdout);

	wget_net_init(); // needed for Windows Sockets

	// 1. parse the URL into a URI
	//    if you want use a non-ascii (international) domain, the second
	//    parameter should be the character encoding of this file (e.g. "iso-8859-1")
	uri = wget_iri_parse("http://www.example.org", NULL);

	// 2. create a HTTP/1.1 GET request.
	//    the only default header is 'Host: www.example.com' (taken from uri)
	req = wget_http_create_request(uri, "GET");

	// 3. add HTTP headers as you wish
	wget_http_add_header(req, "User-Agent", "TheUserAgent/0.5");

	// libwget also supports gzip'ed or deflated response bodies
	wget_http_add_header(req, "Accept-Encoding", "gzip, deflate");
	wget_http_add_header(req, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	wget_http_add_header(req, "Accept-Language", "en-us,en;q=0.5");

	wget_http_request_set_int(req, WGET_HTTP_RESPONSE_KEEPHEADER, 1);

	// use keep-alive if you want to send more requests on the same connection
	// http_add_header(req, "Connection", "keep-alive");

	// you need cookie support ? just #define COOKIE_SUPPORT or remove the #ifdef/#endif
	// 'keep_session_cookies' should be 0 or 1
#ifdef COOKIE_SUPPORT
	const char *cookie_string;

	// init cookie database
	cookies = wget_cookie_db_init(NULL);
	wget_cookie_set_keep_session_cookies(cookies, 1);

	// load public suffixes for cookie validation from file (instead of using internal PSL data)
	// just works if Wget has been compiled with libpsl
	wget_cookie_db_load_psl(cookies, "public_suffixes.txt");

	// load cookie-store
	wget_cookie_db_load(cookies, "cookies.txt");

	// enrich the HTTP request with the uri-related cookies we have
	if ((cookie_string = wget_cookie_create_request_header(cookies, uri))) {
		wget_http_add_header(req, "Cookie", cookie_string);
		wget_xfree(cookie_string);
	}
#endif

	// 4. establish connection to the host/port given by uri
	// well, we could have done this directly after wget_iri_parse(), since
	// http_open() works semi-async and returns immediately after domain name lookup.
	wget_http_open(&conn, uri);

	if (conn) {
		wget_http_response *resp;

		if (wget_http_send_request(conn, req) == 0) {
			resp = wget_http_get_response(conn);

			if (!resp)
				goto out;

			// server doesn't support or want keep-alive
			if (!resp->keep_alive)
				wget_http_close(&conn);

#ifdef COOKIE_SUPPORT
			// check and normalization of received cookies
			wget_cookie_normalize_cookies(uri, resp->cookies);

			// put cookies into cookie-store (also known as cookie-jar)
			wget_cookie_store_cookies(cookies, resp->cookies);

			// save cookie-store to file
			wget_cookie_db_save(cookies, "cookies.txt");
#endif

			// let's assume the body isn't binary (doesn't contain \0)
			wget_info_printf("%s%s\n", resp->header->data, resp->body->data);

			wget_http_free_response(&resp);
		}
	}

out:
#ifdef COOKIE_SUPPORT
	wget_cookie_db_free(&cookies);
#endif
	wget_http_close(&conn);
	wget_http_free_request(&req);
	wget_iri_free(&uri);

	wget_net_deinit(); // needed for Windows Sockets

	return 0;
}

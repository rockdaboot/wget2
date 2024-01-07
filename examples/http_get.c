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
 * Simple demonstration how to download an URL with high level API functions.
 *
 */

#include <stdlib.h>
#include <wget.h>

int main(int argc WGET_GCC_UNUSED, const char *const *argv WGET_GCC_UNUSED)
{
	wget_http_connection *conn = NULL;
	wget_http_response *resp;

	// set up libwget global configuration
	wget_global_init(
		WGET_DEBUG_STREAM, stderr,
		WGET_ERROR_STREAM, stderr,
		WGET_INFO_STREAM, stdout,
		WGET_DNS_CACHING, 1,
		WGET_COOKIES_ENABLED, 1,
		WGET_COOKIE_SUFFIXES, "public_suffixes.txt",
		WGET_COOKIE_FILE, "cookies.txt",
		WGET_COOKIE_KEEPSESSIONCOOKIES, 1,
		// WGET_BIND_ADDRESS, "127.0.0.1:6666",
		// WGET_NET_FAMILY_EXCLUSIVE, WGET_NET_FAMILY_IPV4, // or WGET_NET_FAMILY_IPV6 or WGET_NET_FAMILY_ANY
		// WGET_NET_FAMILY_PREFERRED, WGET_NET_FAMILY_IPV4, // or WGET_NET_FAMILY_IPV6 or WGET_NET_FAMILY_ANY
		0);

	// execute an HTTP GET request and return the response
	resp = wget_http_get(
		WGET_HTTP_URL, "https://example.com",
		// WGET_HTTP_URL_ENCODING, "utf-8",
		WGET_HTTP_HEADER_ADD, "User-Agent", "Mozilla/5.0",
		WGET_HTTP_HEADER_ADD, "Accept-Encoding", "gzip, deflate",
		WGET_HTTP_HEADER_ADD, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		WGET_HTTP_HEADER_ADD, "Accept-Language", "en-us,en;q=0.5",
		// WGET_HTTP_PROXY, "myproxy.com:9375",
		// WGET_HTTP_HEADER_SAVEAS_STREAM, stdout,
		// WGET_HTTP_BODY_SAVEAS_STREAM, stdout,
		WGET_HTTP_MAX_REDIRECTIONS, 5,
		WGET_HTTP_CONNECTION_PTR, &conn,
		// WGET_HTTP_RESPONSE_PTR, &resp,
		0);

	if (resp) {
		// let's assume the body is printable
		printf("%s%s\n", resp->header->data, resp->body->data);

		// free the response
		wget_http_free_response(&resp);
	}

	// close connection if still open
	wget_http_close(&conn);

	// free resources - needed for valgrind testing
	wget_global_deinit();

	return 0;
}

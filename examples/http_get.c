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
 * Example for retrieving and parsing an HTTP URI
 *
 * Changelog
 * 16.01.2013  Tim Ruehsen  created
 *
 * Simple demonstration how to download an URL with high level API functions.
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <libmget.h>

int main(int argc G_GNUC_MGET_UNUSED, const char *const *argv G_GNUC_MGET_UNUSED)
{
	mget_http_connection_t *conn = NULL;
	mget_http_response_t *resp;

	// set up libmget global configuration
	mget_global_init(
		MGET_DEBUG_STREAM, stderr,
		MGET_ERROR_STREAM, stderr,
		MGET_INFO_STREAM, stdout,
		MGET_DNS_CACHING, 1,
		MGET_COOKIES_ENABLED, 1,
		MGET_COOKIE_SUFFIXES, "public_suffixes.txt",
		MGET_COOKIE_FILE, "cookies.txt",
		MGET_COOKIE_KEEPSESSIONCOOKIES, 1,
		// MGET_BIND_ADDRESS, "127.0.0.1:6666",
		// MGET_NET_FAMILY_EXCLUSIVE, MGET_NET_FAMILY_IPV4, // or MGET_NET_FAMILY_IPV6 or MGET_NET_FAMILY_ANY
		// MGET_NET_FAMILY_PREFERRED, MGET_NET_FAMILY_IPV4, // or MGET_NET_FAMILY_IPV6 or MGET_NET_FAMILY_ANY
		NULL);

	// execute an HTTP GET request and return the response
	resp = mget_http_get(
		MGET_HTTP_URL, "http://example.com",
		// MGET_HTTP_URL_ENCODING, "utf-8",
		MGET_HTTP_HEADER_ADD, "User-Agent", "Mozilla/5.0",
		MGET_HTTP_HEADER_ADD, "Accept-Encoding", "gzip, deflate",
		MGET_HTTP_HEADER_ADD, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		MGET_HTTP_HEADER_ADD, "Accept-Language", "en-us,en;q=0.5",
		// MGET_HTTP_PROXY, "myproxy.com:9375",
		// MGET_HTTP_HEADER_SAVEAS_STREAM, stdout,
		// MGET_HTTP_BODY_SAVEAS_STREAM, stdout,
		MGET_HTTP_MAX_REDIRECTIONS, 5,
		MGET_HTTP_CONNECTION_PTR, &conn,
		// MGET_HTTP_RESPONSE_PTR, &resp,
		NULL);

	if (resp) {
		// let's assume the body is printable
		printf("%s%s\n", resp->header->data, resp->body->data);

		// free the response
		mget_http_free_response(&resp);
	}

	// close connection if still open
	mget_http_close(&conn);

	// free resources - needed for valgrind testing
	mget_global_deinit();

	return 0;
}

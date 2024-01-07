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
 * 08.06.2016  Tim Ruehsen  created
 *
 * Download multiple files from a server async/parallel.
 * With HTTP/1.1: This uses HTTP pipelining, experimental and not working with all servers
 * With HTTP/2.0: response data comes in parallel streams
 *
 */

#include <stdlib.h>
#include <wget.h>

// number of elements within an array
#define countof(a) (sizeof(a)/sizeof(*(a)))

// Wget's standard OCSP database file
#define OCSP_DB ".wget-ocsp"

int main(void)
{
	const char *urls[] = {
		"https://www.google.de/1.html",
		"https://www.google.de/2.html",
		"https://www.google.de/4.html",
	};
	wget_iri *iris[countof(urls)] = { NULL };
	wget_http_request *reqs[countof(urls)] = { NULL };
	wget_http_connection *conn = NULL;


	wget_global_init(
		WGET_DEBUG_STREAM, stderr,
		WGET_ERROR_STREAM, stderr,
		WGET_INFO_STREAM, stderr,
		WGET_DNS_CACHING, 1,
		0);

	// SSL: share Wget's OCSP cache for speed improvements
	wget_ocsp_db *ocsp_db = wget_ocsp_db_init(NULL, OCSP_DB);
	wget_ocsp_db_load(ocsp_db);
	wget_ssl_set_config_string(WGET_SSL_OCSP_CACHE, (const char *) ocsp_db);

	// SSL: print information about server certs
	wget_ssl_set_config_int(WGET_SSL_PRINT_INFO, 1);

	// SSL: switch HTTP/2.0 on/off via ALPN
	// wget_ssl_set_config_string(WGET_SSL_ALPN, config.http2 ? "h2,http/1.1" : NULL);

	for (unsigned it = 0; it < countof(urls); it++) {
		// 1. parse the URL into a URI
		//    if you want use a non-ascii (international) domain, the second
		//    parameter should be the character encoding of this file (e.g. "iso-8859-1")
		iris[it] = wget_iri_parse(urls[it], NULL);

		// 2. create a HTTP GET request.
		//    the only default header is 'Host: <domain>' (taken from uri)
		reqs[it] = wget_http_create_request(iris[it], "GET");

		// 3. add HTTP headers as you wish
		wget_http_add_header(reqs[it], "User-Agent", "TheUserAgent/0.5");

		// libwget also supports gzip'ed or deflated response bodies
		wget_http_add_header(reqs[it], "Accept-Encoding", "gzip, deflate");
		wget_http_add_header(reqs[it], "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		wget_http_add_header(reqs[it], "Accept-Language", "en-us,en;q=0.5");

		// keep the received response header in 'resp->header'
		wget_http_request_set_int(reqs[it], WGET_HTTP_RESPONSE_KEEPHEADER, 1);

		// use keep-alive if you want to send more requests on the same connection
		// http_add_header(req[it], "Connection", "keep-alive");
	}

	// establish connection to the host/port given
	wget_http_open(&conn, iris[0]);

	if (!conn)
		goto out;

	for (unsigned it = 0; it < countof(urls); it++) {
		if (wget_http_send_request(conn, reqs[it]))
			goto out;
	}

	for (;;) {
		wget_http_response *resp = wget_http_get_response(conn);

		if (!resp)
			goto out; // done or severe error

		// let's assume the body isn't binary (doesn't contain \0)
		if (resp->header)
			wget_info_printf("%s\n", resp->header->data);
		if (resp->body)
			wget_info_printf("%s\n", resp->body->data);

		wget_http_free_response(&resp);
	}

out:
	wget_http_close(&conn);

	for (unsigned it = 0; it < countof(urls); it++) {
		wget_http_free_request(&reqs[it]);
		wget_iri_free(&iris[it]);
	}

	wget_ocsp_db_save(ocsp_db);
	wget_ocsp_db_free(&ocsp_db);

	return 0;
}

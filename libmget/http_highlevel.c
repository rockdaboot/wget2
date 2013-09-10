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
 * Highlevel HTTP functions
 *
 * Changelog
 * 21.01.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include <libmget.h>
#include "private.h"

MGET_HTTP_RESPONSE *mget_http_get(int first_key, ...)
{
	MGET_VECTOR *headers = mget_vector_create(8, 8, NULL);
	MGET_IRI *uri = NULL;
	MGET_HTTP_CONNECTION *conn = NULL, **connp = NULL;
	MGET_HTTP_REQUEST *req;
	MGET_HTTP_RESPONSE *resp = NULL;
	MGET_VECTOR *challenges = NULL;
	FILE *saveas_stream = NULL;
	int(*saveas_handler)(void *, const char *, size_t) = NULL;
	int saveas_fd = -1;
	int (*header_handler)(void *, MGET_HTTP_RESPONSE *) = NULL;
	va_list args;
	const char *url = NULL,	*url_encoding = NULL;
	const char *http_username = NULL, *http_password = NULL;
	int key, it, max_redirections = 5, redirection_level = 0;

	struct {
		unsigned int
			cookies_enabled : 1,
			keep_header : 1,
			free_uri : 1;
	} bits = {
		.cookies_enabled = !!mget_global_get_int(MGET_COOKIES_ENABLED)
	};
	
	va_start(args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case MGET_HTTP_URL:
			url = va_arg(args, const char *);
			break;
		case MGET_HTTP_URI:
			uri = va_arg(args, MGET_IRI *);
			break;
		case MGET_HTTP_URL_ENCODING:
			url_encoding = va_arg(args, const char *);
			break;
		case MGET_HTTP_HEADER_ADD:
		{
			const char *header = va_arg(args, const char *);
			mget_vector_add_noalloc(headers, header);
			break;
		}
		case MGET_HTTP_CONNECTION_PTR:
			connp = va_arg(args, MGET_HTTP_CONNECTION **);
			if (connp)
				conn = *connp;
			break;
		case MGET_HTTP_RESPONSE_KEEPHEADER:
			bits.keep_header = va_arg(args, int);
			break;
		case MGET_HTTP_MAX_REDIRECTIONS:
			max_redirections = va_arg(args, int);
			break;
		case MGET_HTTP_BODY_SAVEAS_STREAM:
			saveas_stream = va_arg(args, FILE *);
			break;
		case MGET_HTTP_BODY_SAVEAS_FUNC:
			saveas_handler = va_arg(args, int(*)(void *, const char *, size_t));
			break;
		case MGET_HTTP_BODY_SAVEAS_FD:
			saveas_fd = va_arg(args, int);
			break;
		case MGET_HTTP_HEADER_FUNC:
			header_handler = va_arg(args, int (*)(void *, MGET_HTTP_RESPONSE *));
			break;
		default:
			error_printf(_("Unknown option %d\n"), key);
			goto out;
		}
	}
	va_end(args);

	if (url && !uri) {
		uri = mget_iri_parse(url, url_encoding);
		bits.free_uri = 1;
	}

	if (!uri) {
		error_printf(_("Missing URL/URI\n"));
		goto out;
	}

	while (uri && redirection_level <= max_redirections) {
		// create a HTTP/1.1 GET request.
		// the only default header is 'Host: domain' (taken from uri)
		req = http_create_request(uri, "GET");

		// add HTTP headers
		for (it = 0; it < mget_vector_size(headers); it++) {
			http_add_header_line(req, mget_vector_get(headers, it));
		}

		if (challenges) {
			// There might be more than one challenge, we could select the securest one.
			// For simplicity and testing we just take the first for now.
			// the following adds an Authorization: HTTP header
			http_add_credentials(req, mget_vector_get(challenges, 0), http_username, http_password);
			http_free_challenges(&challenges);
		}

		// use keep-alive if you want to send more requests on the same connection
		// http_add_header_line(req, "Connection: keep-alive\r\n");

		// enrich the HTTP request with the uri-related cookies we have
		if (bits.cookies_enabled) {
			const char *cookie_string;
			if ((cookie_string = mget_cookie_create_request_header(uri))) {
				http_add_header(req, "Cookie", cookie_string);
				xfree(cookie_string);
			}
		}

		// open/reopen/reuse HTTP/HTTPS connection
		if (conn && !mget_strcmp(conn->esc_host, uri->host) &&
			conn->scheme == uri->scheme &&
			!mget_strcmp(conn->port, uri->resolv_port))
		{
			debug_printf("reuse connection %s\n", conn->esc_host);
		} else {
			if (conn) {
				debug_printf("close connection %s\n", conn->esc_host);
				http_close(&conn);
			}
			conn = http_open(uri);
			if (conn)
				debug_printf("opened connection %s\n", conn->esc_host);
		}

		if (conn) {
			if (http_send_request(conn, req) == 0) {
				if (saveas_stream)
					resp = http_get_response_stream(conn, header_handler, saveas_stream, MGET_HTTP_RESPONSE_KEEPHEADER);
				else if (saveas_handler)
					resp = http_get_response_func(conn, header_handler, saveas_handler, NULL, MGET_HTTP_RESPONSE_KEEPHEADER);
				else if (saveas_fd != -1)
					resp = http_get_response_fd(conn, header_handler, saveas_fd, MGET_HTTP_RESPONSE_KEEPHEADER);
				else
					resp = http_get_response(conn, header_handler, req, MGET_HTTP_RESPONSE_KEEPHEADER);
			}
		}

		http_free_request(&req);

		if (!resp)
			goto out;

		// server doesn't support or want keep-alive
		if (!resp->keep_alive)
			http_close(&conn);

		if (bits.cookies_enabled) {
			// check and normalization of received cookies
			mget_cookie_normalize_cookies(uri, resp->cookies);

			// put cookies into cookie-store (also known as cookie-jar)
			mget_cookie_store_cookies(resp->cookies);
		}

		if (resp->code == 401 && !challenges) { // Unauthorized
			if ((challenges = resp->challenges)) {
				resp->challenges = NULL;
				http_free_response(&resp);
				continue; // try again with credentials
			}
			break;
		}

		// 304 Not Modified
		if (resp->code / 100 == 2 || resp->code / 100 >= 4 || resp->code == 304)
			break; // final response

		if (resp->location) {
			char uri_sbuf[1024];
			mget_buffer_t uri_buf;

			// if relative location, convert to absolute
			mget_buffer_init(&uri_buf, uri_sbuf, sizeof(uri_sbuf));
			mget_iri_relative_to_abs(uri, resp->location, strlen(resp->location), &uri_buf);

			if (bits.free_uri)
				mget_iri_free(&uri);

			uri = mget_iri_parse(uri_buf.data, NULL);
			bits.free_uri = 1;

			mget_buffer_deinit(&uri_buf);

			redirection_level++;
			continue;
		}

		break;
	}


out:
	if (connp) {
		*connp = conn;
	} else {
		http_close(&conn);
	}

	http_free_challenges(&challenges);

	mget_vector_clear_nofree(headers);
	mget_vector_free(&headers);

	if (bits.free_uri)
		mget_iri_free(&uri);

	return resp;
}

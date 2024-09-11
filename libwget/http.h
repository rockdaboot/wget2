/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file for private HTTP structures
 */

#ifndef LIBWGET_HTTP_H
# define LIBWGET_HTTP_H

#ifdef WITH_LIBNGHTTP2
#	include <nghttp2/nghttp2.h>
#endif

//wget_http_connection_t abstract type
struct wget_http_connection_st {
	wget_tcp *
		tcp;
	const char *
		esc_host;
	wget_buffer *
		buf;
#ifdef WITH_LIBNGHTTP2
	nghttp2_session *
		http2_session;
#endif
	wget_vector
		*pending_requests; // List of unresponsed requests (HTTP1 only)
	wget_vector
		*received_http2_responses; // List of received (but yet unprocessed) responses (HTTP2 only)
	int
		pending_http2_requests; // Number of unresponsed requests (HTTP2 only)
	wget_iri_scheme
		scheme;
	uint16_t
		port;
	char
		protocol; // WGET_PROTOCOL_HTTP_1_1 or WGET_PROTOCOL_HTTP_2_0
	bool
		print_response_headers : 1,
		abort_indicator : 1,
		proxied : 1,
		goaway : 1;
};

/* HTTP/1.0 status codes from RFC1945 */
#define H_10X(x)        (((x) >= 100) && ((x) < 200))

/* Successful 2xx.  */
#define HTTP_STATUS_OK                    200
#define HTTP_STATUS_CREATED               201
#define HTTP_STATUS_ACCEPTED              202
#define HTTP_STATUS_NO_CONTENT            204
#define HTTP_STATUS_PARTIAL_CONTENTS      206

/* Redirection 3xx.  */
#define HTTP_STATUS_MULTIPLE_CHOICES      300
#define HTTP_STATUS_MOVED_PERMANENTLY     301
#define HTTP_STATUS_MOVED_TEMPORARILY     302
#define HTTP_STATUS_SEE_OTHER             303 /* from HTTP/1.1 */
#define HTTP_STATUS_NOT_MODIFIED          304
#define HTTP_STATUS_TEMPORARY_REDIRECT    307 /* from HTTP/1.1 */

/* Client error 4xx.  */
#define HTTP_STATUS_BAD_REQUEST           400
#define HTTP_STATUS_UNAUTHORIZED          401
#define HTTP_STATUS_FORBIDDEN             403
#define HTTP_STATUS_NOT_FOUND             404
#define HTTP_STATUS_RANGE_NOT_SATISFIABLE 416

int http_connection_is_aborted(wget_http_connection *conn);

void http_fix_broken_server_encoding(wget_http_response *resp);

int http_get_body_cb(void *context, const char *data, size_t length);
int http_decompress_error_handler_cb(wget_decompressor *dc, int err);

int wget_http2_open(wget_http_connection *conn);
void wget_http2_close(wget_http_connection **conn);
int wget_http2_send_request(wget_http_connection *conn, wget_http_request *req);
wget_http_response *wget_http2_get_response_cb(wget_http_connection *conn,
					       wget_server_stats_callback *server_stats_callback);

#endif /* LIBWGET_HTTP_H */

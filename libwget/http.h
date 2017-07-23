/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
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

#ifndef _LIBWGET_HTTP_H
# define _LIBWGET_HTTP_H

#ifdef WITH_LIBNGHTTP2
#	include <nghttp2/nghttp2.h>
#endif

//wget_http_connection_t abstract type
struct _wget_http_connection_st {
	wget_tcp_t *
		tcp;
	const char *
		esc_host;
	const char *
		scheme;
	wget_buffer_t *
		buf;
#ifdef WITH_LIBNGHTTP2
	nghttp2_session *
		http2_session;
#endif
	wget_vector_t
		*pending_requests; // List of unresponsed requests (HTTP1 only)
	wget_vector_t
		*received_http2_responses; // List of received (but yet unprocessed) responses (HTTP2 only)
	int
		pending_http2_requests; // Number of unresponsed requests (HTTP2 only)
	uint16_t
		port;
	char
		protocol; // WGET_PROTOCOL_HTTP_1_1 or WGET_PROTOCOL_HTTP_2_0
	unsigned char
		print_response_headers : 1,
		abort_indicator : 1,
		proxied : 1;
};

#endif /* _LIBWGET_HTTP_H */

/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for HTTP routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 * Resources:
 * RFC 2616
 *
 */

#ifndef _MGET_HTTP_H
#define _MGET_HTTP_H

#include "vector.h"
#include "job.h"
#include "net.h"
#include "buffer.h"
#include "iri.h"

// FLAGS for http_get_file()
#define HTTP_FLG_USE_FILE (1<<0) // use filename without path for saving files
#define HTTP_FLG_USE_PATH (1<<1) // use complete path for saving files
#define HTTP_FLG_CLOBBER  (1<<2) // overwrite existing files

typedef struct {
	const char
		*name,
		*value;
} HTTP_HEADER_PARAM;

typedef struct {
	const char
		*uri,
		*type;
	int
		pri;
	enum {
		link_rel_describedby,
		link_rel_duplicate
	} rel;
} HTTP_LINK;

typedef struct {
	const char
		*algorithm,
		*encoded_digest;
} HTTP_DIGEST;

enum {
	transfer_encoding_identity,
	transfer_encoding_chunked
};

// keep the request as simple as possible
typedef struct {
	const char
		*resource;
	char
		method[8]; // we just need HEAD, GET and POST
	VECTOR
		*lines;
} HTTP_REQUEST;

// just parse the header lines that we need
typedef struct {
	VECTOR
		*links,
		*digests;
	const char
		*content_type,
		*location;
	buffer_t
		*body;
	size_t
		content_length;
	char
		reason[32];
	short
		major,
		minor,
		code; // request only status code
	char
		transfer_encoding,
		content_encoding,
		content_length_valid,
		keep_alive;
} HTTP_RESPONSE;

typedef struct {
	tcp_t
		tcp;
	struct addrinfo
		*addrinfo,
		*ai;
	const char
		*host,
		*port,
		*scheme;
	buffer_t
		*buf;
} HTTP_CONNECTION;

int
	http_isseperator(char c),
	http_istoken(char c),
	http_istext(char c);
const char
	*http_parse_token(const char *s, const char **token) NONNULL_ALL,
	*http_parse_quoted_string(const char *s, const char **qstring) NONNULL_ALL,
	*http_parse_param(const char *s, const char **param, const char **value) NONNULL_ALL,
	*http_parse_name(const char *s, const char **name) NONNULL_ALL,
	*http_parse_name_fixed(const char *s, char *name, size_t name_size) NONNULL_ALL,
	*http_parse_link(HTTP_LINK *link, const char *s) NONNULL_ALL,
	*http_parse_digest(HTTP_DIGEST *digest, const char *s) NONNULL_ALL,
	*http_parse_location(const char *s, const char **location) NONNULL_ALL,
	*http_parse_transfer_encoding(const char *s, char *transfer_encoding) NONNULL_ALL,
	*http_parse_content_type(const char *s, const char **content_type) NONNULL_ALL,
	*http_parse_content_encoding(const char *s, char *content_encoding) NONNULL_ALL,
	*http_parse_connection(const char *s, char *keep_alive) NONNULL_ALL;
void
	http_add_param(VECTOR **params, HTTP_HEADER_PARAM *param) NONNULL_ALL,
	http_add_header_vprintf(HTTP_REQUEST *req, const char *fmt, va_list args) PRINTF_FORMAT(2,0) NONNULL_ALL,
	http_add_header_printf(HTTP_REQUEST *req, const char *fmt, ...) PRINTF_FORMAT(2,3) NONNULL_ALL,
	http_add_header_line(HTTP_REQUEST *req, const char *line) NONNULL_ALL,
	http_add_header(HTTP_REQUEST *req, const char *name, const char *value) NONNULL_ALL;

int
	http_free_param(HTTP_HEADER_PARAM *param),
	http_free_digest(HTTP_DIGEST *digest),
	http_free_link(HTTP_LINK *link);
void
	http_free_digests(VECTOR *digests),
	http_free_links(VECTOR *link),
//	http_free_header(HTTP_HEADER **header),
	http_free_request(HTTP_REQUEST **req),
	http_free_response(HTTP_RESPONSE **resp);

HTTP_RESPONSE
	*http_read_header(const IRI *iri) NONNULL_ALL,
	*http_get_header(IRI *iri) NONNULL_ALL,
	*http_parse_response(char *buf) NONNULL_ALL,
	*http_get_response_cb(HTTP_CONNECTION *conn, HTTP_REQUEST *req,
								 int (*parse_body)(void *context, const char *data, size_t length),
								 void *context) NONNULL(1,3,4),
//	*http_get_response_mem(HTTP_CONNECTION *conn, HTTP_REQUEST *req) NONNULL_ALL,
	*http_get_response(HTTP_CONNECTION *conn, HTTP_REQUEST *req) NONNULL(1),
	*http_get_response_fd(HTTP_CONNECTION *conn, int fd) NONNULL_ALL;

HTTP_CONNECTION
	*http_open(const IRI *iri) NONNULL_ALL;
HTTP_REQUEST
	*http_create_request(const IRI *iri, const char *method) NONNULL_ALL;
void
	http_close(HTTP_CONNECTION **conn) NONNULL_ALL;
int
	http_send_request(HTTP_CONNECTION *conn, HTTP_REQUEST *req) NONNULL_ALL;
ssize_t
	http_request_to_buffer(HTTP_REQUEST *req, buffer_t *buf) NONNULL_ALL;

#endif /* _MGET_HTTP_H */

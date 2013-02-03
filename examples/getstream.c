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
 * Example for loading and playing a .m3u stream
 *
 * Changelog
 * 03.02.2013  Tim Ruehsen  created
 *
 * Call it like: ./getstream | vlc -- -
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <strings.h>
#include <ctype.h>

#include <stdlib.h>
#include <libmget.h>

int main(int argc G_GNUC_MGET_UNUSED, const char *const *argv G_GNUC_MGET_UNUSED)
{
	MGET_HTTP_RESPONSE *resp;
	char *stream_url = NULL;

	// set up libmget global configuration
	mget_global_init(
		// MGET_DEBUG_STREAM, stderr,
		MGET_ERROR_STREAM, stderr,
		MGET_INFO_STREAM, stderr,
		NULL);

	// execute an HTTP GET request and return the response
	resp = mget_http_get(
		MGET_HTTP_URL, "http://www.ndr.de/resources/metadaten/audio/m3u/n-joy.m3u",
		MGET_HTTP_HEADER_ADD, "User-Agent: Mozilla/5.0",
		MGET_HTTP_MAX_REDIRECTIONS, 5,
		NULL);

	if (resp && resp->code==200 && !strcasecmp(resp->content_type, "audio/x-mpegurl")) {
		char *p1 = resp->body->data, *p2 = p1;

		while (isspace(*p1)) p1++; // skip whitespace
		for (p2 =p1; !isspace(*p2);) p2++;

		stream_url = strndup(p1, p2 - p1);
	}

	// free the response
	http_free_response(&resp);

	if (stream_url) {
		resp = mget_http_get(
			MGET_HTTP_URL, stream_url,
			MGET_HTTP_HEADER_ADD, "User-Agent: Mozilla/5.0",
			// MGET_HTTP_HEADER_ADD, "Icy-Metadata: 1",
			// MGET_HTTP_HEADER_RESPONSE_FUNC, ,
			// MGET_HTTP_HEADER_SAVEAS_STREAM, stdout,
			MGET_HTTP_BODY_SAVEAS_STREAM, stdout,
			NULL);

		http_free_response(&resp);
	}

	// free resources - needed for valgrind testing
	mget_global_deinit();

	return 0;
}

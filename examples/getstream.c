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

static char *stream_name;
static char *streamdata;
static char metadata[255*16];
static int metaint, streamdatalen, metadatalen;

static void examine_response_header(void *context, MGET_HTTP_RESPONSE *resp)
{
	// <context> depends on MGET_HTTP_BODY_SAVEAS_* option given to mget_http_get().
	// The response header is so far parsed into <resp> structure.
	// If you are looking for header that are ignored by libmget, parse them yourself.

	if (resp->header) {
		char key[64], value[128], *p;

		// simplistic scanning (just an example)
		// won't work with split lines and not with empty values
		for (p = strchr(resp->header->data, '\n'); p && sscanf(p + 1, " %63[a-zA-z-] : %127[^\r\n]", key, value) >= 1; p = strchr(p + 1, '\n')) {
			// mget_info_printf("%s = %s\n", key, value);
			if (!strcasecmp(key, "icy-name"))
				stream_name = strdup(value);
			*value=0;
		}
	}

	if ((metaint = resp->icy_metaint)) {
		streamdata = malloc(metaint);
	}
}

static void parse_body(void *context, const char *data, size_t len)
{
	// any stream data received is piped through this function

	if (metaint) {
		static int collect_metadata;
		static size_t metadatasize;

		while (len) {
			if (collect_metadata) {
				for (; len && metadatasize; metadatasize--, len--)
					metadata[metadatalen++] = *data++;

				if (metadatasize == 0) {
					collect_metadata = 0;
					printf("%.*s\n", metadatalen, metadata);
				}
			} else {
				for (; len && streamdatalen < metaint; len--)
					streamdata[streamdatalen++] = *data++;

				if (len) {
					if ((metadatasize = ((unsigned char)(*data++)) * 16) > 0)
						collect_metadata = 1;
					len--;
					metadatalen = 0;
					streamdatalen = 0;
				}
			}
		}
	}
}

int main(int argc G_GNUC_MGET_UNUSED, const char *const *argv G_GNUC_MGET_UNUSED)
{
	MGET_HTTP_RESPONSE *resp;
	char *stream_url = NULL;

	// set up libmget global configuration
	mget_global_init(
//		MGET_DEBUG_STREAM, stderr,
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

	// The icy-metaint: response header indicates the <size> of the data blocks.
	// The stream starts with <size> data bytes followed by one single byte, that holds the size of the metadata divided by 16.
	// That byte usually is 0, because there is no metadata.
	// After the metadata, again <size> bytes stream data follow, and so on.
	if (stream_url) {
		resp = mget_http_get(
//			MGET_HTTP_URL, stream_url,
			MGET_HTTP_URL, "http://streaming207.radionomy.com:80/Gothica",
			MGET_HTTP_HEADER_ADD, "User-Agent: Mozilla/5.0",
			MGET_HTTP_HEADER_ADD, "Icy-Metadata: 1",
			MGET_HTTP_HEADER_FUNC, examine_response_header,
			// MGET_HTTP_HEADER_SAVEAS_STREAM, stdout,
			MGET_HTTP_BODY_SAVEAS_FUNC, parse_body,
			NULL);

		http_free_response(&resp);
	}

	// free resources - needed for valgrind testing
	mget_global_deinit();

	return 0;
}

/*
 * Copyright(c) 2013 Tim Ruehsen
 * Copyright(c) 2015 Free Software Foundation, Inc.
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Example for retrieving a SHOUTCAST stream and showing the metainfo (using a .m3u playlist)
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
#include <libwget.h>

static char *stream_name;
static char *streamdata;
static char metadata[255*16];
static int metaint, streamdatalen, metadatalen;

// callback function to examine received HTTP response header
// <context> depends on WGET_HTTP_BODY_SAVEAS_* option given to wget_http_get().
// The response header is has been parsed into <resp> structure.
static void header_callback(void *context G_GNUC_WGET_UNUSED, wget_http_response_t *resp)
{
	// If you are looking for header that are ignored by libwget, parse them yourself.

	if (resp->header) {
		char key[64], value[128];

		// simplistic scanning (just an example)
		// won't work with split lines and not with empty values
		for (char *p = strchr(resp->header->data, '\n'); p && sscanf(p + 1, " %63[a-zA-z-] : %127[^\r\n]", key, value) >= 1; p = strchr(p + 1, '\n')) {
			// wget_info_printf("%s = %s\n", key, value);
			if (!wget_strcasecmp_ascii(key, "icy-name")) {
				stream_name = strdup(value);
				break;
			}
			*value=0;
		}
	}

	if ((metaint = resp->icy_metaint)) {
		streamdata = malloc(metaint);
	}
}

// callback function to handle incoming stream data
static void stream_callback(void *context G_GNUC_WGET_UNUSED, const char *data, size_t len)
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

int main(int argc G_GNUC_WGET_UNUSED, const char *const *argv G_GNUC_WGET_UNUSED)
{
	wget_http_response_t *resp;
	char *stream_url = NULL;

	// set up libwget global configuration
	wget_global_init(
//		WGET_DEBUG_STREAM, stderr,
		WGET_ERROR_STREAM, stderr,
		WGET_INFO_STREAM, stderr,
		NULL);

	// get and parse the m3u playlist file
	resp = wget_http_get(
		WGET_HTTP_URL, "http://listen.radionomy.com/gothica.m3u",
		NULL);

	if (resp && resp->code == 200 && !wget_strcasecmp_ascii(resp->content_type, "audio/x-mpegurl")) {
		wget_buffer_trim(resp->body); // remove leading and trailing whitespace
		stream_url = strndup(resp->body->data, resp->body->length);
	}

	// free the response
	wget_http_free_response(&resp);

	// The icy-metaint: response header indicates the <size> of the data blocks.
	// The stream starts with <size> data bytes followed by one single byte, that holds the size of the metadata divided by 16.
	// That byte usually is 0, because there is no metadata.
	// After the metadata, again <size> bytes stream data follow, and so on.
	if (stream_url) {
		resp = wget_http_get(
			WGET_HTTP_URL, stream_url,
			WGET_HTTP_HEADER_ADD, "Icy-Metadata", "1", // we want in-stream title/actor information
			WGET_HTTP_HEADER_FUNC, header_callback, // callback used to parse special headers like 'Icy-Name'
			// WGET_HTTP_HEADER_SAVEAS_STREAM, stdout,
			WGET_HTTP_BODY_SAVEAS_FUNC, stream_callback, // callback to cut title info out of audio stream
			NULL);

		wget_http_free_response(&resp);
	}

	// free resources - needed for valgrind testing
	wget_global_deinit();

	return 0;
}

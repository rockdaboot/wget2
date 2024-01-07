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
 * Example for retrieving a SHOUTCAST stream and showing the metainfo (using a .m3u playlist)
 *
 * Changelog
 * 03.02.2013  Tim Ruehsen  created
 *
 * Print out the embedded stream metainfo (e.g. title of currently played song) to STDERR.
 * Send the stream data to STDOUT.
 *
 * Playing MP3 streams on the console:
 *   examples/getstream URL| mpg321 -q -
 *
 * Playing OGG on the console:
 *   examples/getstream URL|sox -t ogg - -t mp3 -|mpg321 -
 * or without MP3 intermediate format:
 *   examples/getstream URL|sox -t ogg - -t s16 -|aplay -f S16 -c 2 -r 44100
 *
 * To switch debug output on, uncomment
 * //		WGET_DEBUG_STREAM, stderr,
 * and 'make' again.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wget.h>

static char *stream_name;
static char *streamdata;
static char metadata[255*16];
static int metaint, streamdatalen, metadatalen;

// callback function to examine received HTTP response header
// <context> depends on WGET_HTTP_BODY_SAVEAS_* option given to wget_http_get().
// The response header is has been parsed into <resp> structure.
static wget_http_header_callback header_callback;
static int header_callback(wget_http_response *resp, void *context WGET_GCC_UNUSED)
{
	// If you are looking for header that are ignored by libwget, parse them yourself.

	if (resp->header) {
		char key[64], value[128] = "";

		// simplistic scanning (just an example)
		// won't work with split lines
		for (char *p = strchr(resp->header->data, '\n'); p && sscanf(p + 1, " %63[a-zA-z-] : %127[^\r\n]", key, value) >= 1; p = strchr(p + 1, '\n')) {
			// wget_info_printf("%s = %s\n", key, value);
			if (!wget_strcasecmp_ascii(key, "icy-name")) {
				stream_name = wget_strdup(value);
				break;
			}
			*value = 0;
		}
	}

	if ((metaint = resp->icy_metaint)) {
		streamdata = wget_malloc(metaint);
	}

	return 0; // OK, continue
}

// callback function to handle incoming stream data
static wget_http_body_callback stream_callback;
static int stream_callback(wget_http_response *resp WGET_GCC_UNUSED, void *context WGET_GCC_UNUSED, const char *data, size_t len)
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
					wget_info_printf("%.*s\n", metadatalen, metadata);
				}
			} else {
				for (; len && streamdatalen < metaint; len--)
					streamdata[streamdatalen++] = *data++;

				if (len) {
					if ((metadatasize = ((unsigned char)(*data++)) * 16) > 0)
						collect_metadata = 1;
					len--;

					fwrite(streamdata, 1, streamdatalen, stdout);
					metadatalen = 0;
					streamdatalen = 0;
				}
			}
		}
	} else {
		// no embedded stream information, just raw audio data
		fwrite(data, 1, len, stdout);
	}

	return 0; // OK, continue
}

static char *strcasestr_ascii(const char *haystack, const char *needle)
{
	size_t needle_len = strlen(needle);

	while (*haystack) {
		if (!wget_strncasecmp_ascii(haystack, needle, needle_len))
			return (char *) haystack;
		haystack++;
	}

	return NULL;
}

int main(int argc, const char *const *argv)
{
	wget_http_response *resp;
	char *stream_url = NULL;

	// set up libwget global configuration
	wget_global_init(
//		WGET_DEBUG_STREAM, stderr,
		WGET_ERROR_STREAM, stderr,
		WGET_INFO_STREAM, stderr,
		0);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <Playlist URL>\n", argv[0]);
		return EXIT_FAILURE;
	}

	// get and parse the m3u playlist file
	resp = wget_http_get(
//		WGET_HTTP_URL, "http://listen.radionomy.com/gothica.m3u",
		WGET_HTTP_URL, argv[1],
		0);

	if (!resp) {
		fprintf(stderr, "Failed to get response from %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	if (resp->code != 200) {
		fprintf(stderr, "Got response code %d\n", resp->code);
		return EXIT_FAILURE;
	}

	// check for common playlist formats and do a naive parsing
	if (!wget_strcasecmp_ascii(resp->content_type, "audio/x-mpegurl") || !wget_strcasecmp_ascii(resp->content_type, "audio/x-pn-realaudio")) {
		// .m3u and .ram format
		char *e, *s;

		e = resp->body->data;
		do {
			s = e;
			while (isspace(*s)) s++;
			if (!*s) break;

			for (e = s; *e && *e != '\r' && *e != '\n'; e++)
				;

			if (*s != '#' && s < e) {
				stream_url = wget_strmemdup(s, e - s);
				break;
			}
		} while (*e);

	} else if (!wget_strcasecmp_ascii(resp->content_type, "audio/x-ms-wax") || !wget_strcasecmp_ascii(resp->content_type, "video/x-ms-asf")) {
		// .wax/.asx format <ASX VERSION="3.0">
		char *p, url[128];

		if ((p = strcasestr_ascii(resp->body->data, " HREF=\"")) && sscanf(p + 7, "%127[^\"]", url) == 1) {
			stream_url = wget_strdup(url);
		} else
			fprintf(stderr, "Failed to parse playlist URL\n");

	} else if (!wget_strcasecmp_ascii(resp->content_type, "application/pls+xml") || !wget_strcasecmp_ascii(resp->content_type, "audio/x-scpls")) {
		// .pls
		char *p, url[128];

		if ((p = strcasestr_ascii(resp->body->data, "File1=")) && sscanf(p + 6, "%127[^\r\n]", url) == 1) {
			stream_url = wget_strdup(url);
		} else
			fprintf(stderr, "Failed to parse playlist URL\n");

	} else if (!wget_strcasecmp_ascii(resp->content_type, "application/xspf+xml")) {
		// .xspf
		char *p, url[128];

		if ((p = strcasestr_ascii(resp->body->data, "<location>")) && sscanf(p + 10, " %127[^< \t\r\n]", url) == 1) {
			stream_url = wget_strdup(url);
		} else
			fprintf(stderr, "Failed to parse playlist URL\n");

	} else {
		fprintf(stderr, "Unsupported type of stream: '%s'\n", resp->content_type);
		return EXIT_FAILURE;
	}

	// free the response
	wget_http_free_response(&resp);

	if (!stream_url) {
		return EXIT_FAILURE;
	}

	// The icy-metaint: response header indicates the <size> of the data blocks.
	// The stream starts with <size> data bytes followed by one single byte, that holds the size of the metadata divided by 16.
	// That byte usually is 0, because there is no metadata.
	// After the metadata, again <size> bytes stream data follow, and so on.
	resp = wget_http_get(
		WGET_HTTP_URL, stream_url,
		WGET_HTTP_HEADER_ADD, "Icy-Metadata", "1", // we want in-stream title/actor information
		WGET_HTTP_HEADER_FUNC, header_callback, NULL, // callback used to parse special headers like 'Icy-Name'
		// WGET_HTTP_HEADER_SAVEAS_STREAM, stdout,
		WGET_HTTP_BODY_SAVEAS_FUNC, stream_callback, NULL, // callback to cut title info out of audio stream
		0);

	wget_http_free_response(&resp);

	// free resources - needed for valgrind testing
	wget_global_deinit();

	return EXIT_SUCCESS;
}

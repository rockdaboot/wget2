/*
 * Copyright (c) 2012 Tim Ruehsen
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
 * css parsing routines
 *
 * Changelog
 * 03.07.2012  Tim Ruehsen  created
 *
 * A parser using the flex tokenizer, created with flex tokens from
 *   https://www.w3.org/TR/css3-syntax/
 *
 * TODO:
 *  - since we are just interested in @import ... and url(...), we could use
 *    a simplistic hand-written parser which might be much smaller and faster
 */

#include <config.h>

#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <c-ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#include <wget.h>
#include "private.h"

#include "css_tokenizer.h"

// see css_tokenizer.c
typedef void* yyscan_t;
int yyget_leng(yyscan_t yyscanner);
char *yyget_text(yyscan_t yyscanner);
typedef struct yy_buffer_state *YY_BUFFER_STATE;
int yylex_init(yyscan_t* scanner);
YY_BUFFER_STATE yy_scan_string(const char * yystr, yyscan_t yyscanner);
YY_BUFFER_STATE yy_scan_bytes(const char * yystr, int len, yyscan_t yyscanner);
int yylex(yyscan_t yyscanner);
int yylex_destroy(yyscan_t yyscanner);
void *yyalloc(size_t size);
void *yyrealloc(void *p, size_t size);

void *yyalloc(size_t size) {
	return wget_malloc(size);
}
void *yyrealloc(void *p, size_t size) {
	return wget_realloc(p, size);
}

void wget_css_parse_buffer(
	const char *buf,
	size_t len,
	wget_css_parse_uri_callback *callback_uri,
	wget_css_parse_encoding_callback *callback_encoding,
	void *user_ctx)
{
	int token;
	size_t length, pos = 0;
	char *text;
	yyscan_t scanner;

	yylex_init(&scanner);
	yy_scan_bytes(buf, (int) len, scanner);

	while ((token = yylex(scanner)) != CSSEOF) {
		if (token == IMPORT_SYM) {
			// e.g. @import "https://example.com/index.html"
			pos += yyget_leng(scanner);

			// skip whitespace before URI/STRING
			while ((token = yylex(scanner)) == S)
				pos += yyget_leng(scanner);

			// now token should be STRING or URI
			if (token == STRING)
				token = URI;
		}

		if (token == URI && callback_uri) {
			// e.g. url(https://example.com/index.html)
			text = yyget_text(scanner);
			length = yyget_leng(scanner);

			if (*text == '\'' || *text == '\"') {
				// a string - remove the quotes
				callback_uri(user_ctx, text + 1, length - 2, pos + 1);
			} else {
				// extract URI from url(...)
				if (!wget_strncasecmp_ascii(text, "url(", 4)) {
					char *otext = text;

					// remove trailing ) and any spaces before
					for (length--; c_isspace(text[length - 1]); length--);

					// remove leading url( and any spaces after
					for (length -= 4, text += 4; length && c_isspace(*text); text++, length--);

					// remove quotes
					if (length && (*text == '\'' || *text == '\"')) {
						text++;
						length--;
					}

					if (length && (text[length - 1] == '\'' || text[length - 1] == '\"'))
						length--;

					callback_uri(user_ctx, text, length, pos + (text - otext));
				}
			}
		} else if (token == CHARSET_SYM && callback_encoding) {
			// e.g. @charset "UTF-8"
			pos += yyget_leng(scanner);

			// skip whitespace before charset name
			while ((token = yylex(scanner)) == S)
				pos += yyget_leng(scanner);

			// now token should be STRING
			if (token == STRING) {
				text = yyget_text(scanner);
				length = yyget_leng(scanner);

				if (*text == '\'' || *text == '\"') {
					// a string - remove the quotes
					callback_encoding(user_ctx, text + 1, length - 2);
				} else {
					// a string without quotes
					callback_encoding(user_ctx, text, length);
				}
			} else {
				error_printf(_("Unknown token after @charset: %d\n"), token);
			}
		}
		pos += yyget_leng(scanner);
	}

	yylex_destroy(scanner);
}

void wget_css_parse_file(
	const char *fname,
	wget_css_parse_uri_callback *callback_uri,
	wget_css_parse_encoding_callback *callback_encoding,
	void *user_ctx)
{
	if (strcmp(fname,"-")) {
		int fd;

		if ((fd = open(fname, O_RDONLY|O_BINARY)) != -1) {
			struct stat st;
			if (fstat(fd, &st) == 0) {
#ifdef HAVE_MMAP
				size_t nread = st.st_size;
				char *buf = mmap(NULL, nread + 1, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
#else
				char *buf=wget_malloc(st.st_size+1);
				size_t nread=read(fd,buf,st.st_size);
#endif

				if (nread > 0) {
					buf[nread] = 0; // PROT_WRITE allows this write, MAP_PRIVATE prevents changes in underlying file system
					wget_css_parse_buffer(buf, st.st_size, callback_uri, callback_encoding, user_ctx);
				}

#ifdef HAVE_MMAP
				munmap(buf, nread);
#else
				xfree(buf);
#endif
			}
			close(fd);
		} else
			error_printf(_("Failed to open %s\n"), fname);
	} else {
		// read data from STDIN.
		// maybe should use yy_scan_bytes instead of buffering into memory.
		char tmp[4096];
		ssize_t nbytes;
		wget_buffer buf;

		wget_buffer_init(&buf, NULL, 4096);

		while ((nbytes = read(STDIN_FILENO, tmp, sizeof(tmp))) > 0) {
			wget_buffer_memcat(&buf, tmp, nbytes);
		}

		if (buf.length)
			wget_css_parse_buffer(buf.data, buf.length, callback_uri, callback_encoding, user_ctx);

		wget_buffer_deinit(&buf);
	}
}

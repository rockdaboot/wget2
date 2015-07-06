/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * css parsing routines
 *
 * Changelog
 * 03.07.2012  Tim Ruehsen  created
 *
 * A parser using the flex tokenizer, created with flex tokens from
 *   http://www.w3.org/TR/css3-syntax/
 *
 * TODO:
 *  - since we are just interested in @import ... and url(...), we could use
 *    a simplistic hand-written parser which might be much smaller and faster
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#include <libmget.h>
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

void mget_css_parse_buffer(
	const char *buf,
	void(*callback_uri)(void *user_ctx, const char *url, size_t len, size_t pos),
	void(*callback_encoding)(void *user_ctx, const char *url, size_t len),
	void *user_ctx)
{
	int token;
	size_t length, pos = 0;
	char *text;
	yyscan_t scanner;

	// let flex operate on buf as a 0 terminated string
	// we could give buflen to this function and use yy_scan_bytes or yy_scan_buffer
	yylex_init(&scanner);
	yy_scan_string(buf, scanner);

	while ((token = yylex(scanner)) != CSSEOF) {
		if (token == IMPORT_SYM) {
			// e.g. @import "http:example.com/index.html"
			pos += yyget_leng(scanner);

			// skip whitespace before URI/STRING
			while ((token = yylex(scanner)) == S)
				pos += yyget_leng(scanner);

			// now token should be STRING or URI
			if (token == STRING)
				token = URI;
		}

		if (token == URI && callback_uri) {
			// e.g. url(http:example.com/index.html)
			text = yyget_text(scanner);
			length = yyget_leng(scanner);

			if (*text == '\'' || *text == '\"') {
				// a string - remove the quotes
				callback_uri(user_ctx, text + 1, length - 2, pos + 1);
			} else {
				// extract URI from url(...)
				if (!strncasecmp(text, "url(", 4)) {
					char *otext = text;

					// remove trailing ) and any spaces before
					for (length--; isspace(text[length - 1]); length--);

					// remove leading url( and any spaces after
					for (length -= 4, text += 4; isspace(*text); text++, length--);

					// remove quotes
					if (*text == '\'' || *text == '\"') {
						text++;
						length -= 2;
					}

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

void mget_css_parse_file(
	const char *fname,
	void(*callback_uri)(void *user_ctx, const char *url, size_t len, size_t pos),
	void(*callback_encoding)(void *user_ctx, const char *url, size_t len),
	void *user_ctx)
{
	int fd;

	if (strcmp(fname,"-")) {
		if ((fd = open(fname, O_RDONLY)) != -1) {
			struct stat st;
			if (fstat(fd, &st) == 0) {
#ifdef HAVE_MMAP
				size_t nread = st.st_size;
				char *buf = mmap(NULL, nread + 1, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
#else
				char *buf=xmalloc(st.st_size+1);
				size_t nread=read(fd,buf,st.st_size);
#endif

				if (nread > 0) {
					buf[nread] = 0; // PROT_WRITE allows this write, MAP_PRIVATE prevents changes in underlying file system
					mget_css_parse_buffer(buf, callback_uri, callback_encoding, user_ctx);
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
		mget_buffer_t *buf = mget_buffer_alloc(4096);

		while ((nbytes = read(STDIN_FILENO, tmp, sizeof(tmp))) > 0) {
			mget_buffer_memcat(buf, tmp, nbytes);
		}

		if (buf->length)
			mget_css_parse_buffer(buf->data, callback_uri, callback_encoding, user_ctx);

		mget_buffer_free(&buf);
	}
}

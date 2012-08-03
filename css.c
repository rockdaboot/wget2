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

#include <stddef.h>
#include <unistd.h>
#include <strings.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "xalloc.h"
#include "log.h"
#include "css_tokenizer.h"
#include "css.h"

// see css_tokenizer.c
typedef void* yyscan_t;
int yyget_leng(yyscan_t yyscanner);
char *yyget_text(yyscan_t yyscanner);
typedef struct yy_buffer_state *YY_BUFFER_STATE;
int yylex_init(yyscan_t* scanner);
YY_BUFFER_STATE yy_scan_string(const char * yystr, yyscan_t yyscanner);
int yylex(yyscan_t yyscanner);
int yylex_destroy(yyscan_t yyscanner);

void css_parse_buffer(
	const char *buf,
	void(*callback)(void *user_ctx, const char *url, size_t len),
	void *user_ctx)
{
	int token;
	int length;
	char *text;
	yyscan_t scanner;

	// let flex operate on buf as a 0 terminated string
	// we could give buflen to this function and use yy_scan_bytes or yy_scan_buffer
	yylex_init(&scanner);
	yy_scan_string(buf, scanner);

	while ((token = yylex(scanner)) != CSSEOF) {
		if (token == IMPORT_SYM) {
			// e.g. @import "http:example.com/index.html"

			// skip whitespace before URI/STRING
			while ((token = yylex(scanner)) == S);

			// now token should be STRING or URI
			if (token == STRING)
				token = URI;
		}

		if (token == URI) {
			// e.g. url(http:example.com/index.html)
			text = yyget_text(scanner);
			length = yyget_leng(scanner);

			if (*text == '\'' || *text == '\"') {
				// a string - remove the quotes
				callback(user_ctx, text + 1, length - 2);
			} else {
				// extract URI from url(...)
				if (!strncasecmp(text, "url(", 4)) {
					// remove trailing ) and any spaces before
					for (length--; isspace(text[length - 1]); length--);

					// remove leading url( and any spaces after
					for (length -= 4, text += 4; isspace(*text); text++, length--);

					// remove quotes
					if (*text == '\'' || *text == '\"') {
						text++;
						length -= 2;
					}
				}
				callback(user_ctx, text, length);
			}
		}
	}

	yylex_destroy(scanner);
}

void css_parse_file(
	const char *fname,
	void(*callback)(void *user_ctx, const char *url, size_t len),
	void *user_ctx)
{
	struct stat st;

	if (stat(fname, &st) == 0) {
		int fd;

		if ((fd = open(fname, O_RDONLY)) != -1) {
			//			char *buf=xmalloc(st.st_size+1);
			//			size_t nread=read(fd,buf,st.st_size);

			size_t nread = st.st_size;
			char *buf = mmap(NULL, nread, PROT_READ, MAP_PRIVATE, fd, 0);

			if (nread > 0) {
				buf[nread] = 0;
				css_parse_buffer(buf, callback, user_ctx);
			}

			munmap(buf, nread);
			close(fd);
			//			xfree(buf);
		}
	}
}

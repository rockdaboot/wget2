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
 * xml parsing routines
 *
 * Changelog
 * 22.06.2012  Tim Ruehsen  created, but needs definitely a rewrite
 *
 * This derives from an old source code that I wrote in 2001.
 * It is short, fast and has a low memory print, BUT it is a hack.
 * It has to be replaced by e.g. libxml2 or something better.
 *
 * HTML parsing is (very) different from XML parsing, see here:
 * http://www.whatwg.org/specs/web-apps/current-work/multipage/parsing.html
 * It is a PITA and should be handled by a specialized, external library !
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <libmget.h>

#include "utils.h"
#include "log.h"
#include "xml.h"

typedef struct XML_CONTEXT XML_CONTEXT;

struct XML_CONTEXT {
	const char
		*buf, // pointer to original start of buffer (0-terminated)
		*p; // pointer to somewhere inside buffer
	char
		*token; // token buffer
	FILE
		*fp; // FILE pointer to XML file
	int
		hints, // XML_HINT...
		(*xml_getc)(XML_CONTEXT *);
	size_t
		token_size, // size of token buffer
		token_len; // used bytes of token buffer (not counting terminating 0 byte)
	void
		*user_ctx, // user context (not needed if we were using nested functions)
		(*xml_ungetc)(XML_CONTEXT *),
		(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *token);
};

// append a char to token buffer

static void tok_putc(XML_CONTEXT *context, char ch)
{
	if (context->token_len >= context->token_size) {
		context->token_size = context->token_size ? context->token_size * 2 : 128;
		context->token = xrealloc(context->token, context->token_size + 1);
	}

	if (ch)
		context->token[context->token_len++] = ch;
	else
		context->token[context->token_len] = ch;
}

static void tok_putmem(XML_CONTEXT *context, const char *data, size_t length)
{
	if (context->token_len + length > context->token_size) {
		context->token_size = context->token_size ? context->token_size * 2 + length : 128;
		context->token = xrealloc(context->token, context->token_size + 1);
	}

	memcpy(context->token + context->token_len, data, length);
	context->token_len += length;
}

// just some shortcuts for readability, undefined after getToken()/getCDATA()
#define tok_putmem(a,l) tok_putmem(context,(a),(l))
#define tok_putc(a) tok_putc(context,(a))
#define xml_getc() context->xml_getc(context)
#define xml_ungetc() context->xml_ungetc(context)

static char *getToken(XML_CONTEXT *context)
{
	int c;

	context->token_len = 0;

	// remove leading spaces
	while ((c = xml_getc()) != EOF && isspace(c));
	if (c == EOF) return NULL;

	tok_putc(c);

	// log_printf("a tok=%s\n",context->token);
	if (c == '<') { // fetch specials, e.g. start of comments '<!--'
		if ((c = xml_getc()) == EOF) return NULL;
		if (c == '?' || c == '/') {
			tok_putc(c);
			tok_putc(0);
			return context->token;
		}
		if (c != '!') {
			xml_ungetc();
			tok_putc(0);
			return context->token;
		}
		tok_putc(c);

		// left: <!--, <![CDATA[ and <!WHATEVER
		if ((c = xml_getc()) == EOF) return NULL;
		if (c == '-') {
			tok_putc(c);
			if ((c = xml_getc()) == EOF) return NULL;
			tok_putc(c);
			if (c == '-') {
				tok_putc(0);
				return context->token;
			}
		} else {
			xml_ungetc();
			tok_putc(0);
			return context->token;
		}
	}

	if (c == '-') { // fetch specials, e.g. end of comments '-->'
		if ((c = xml_getc()) == EOF) return NULL;
		if (c != '-') {
			xml_ungetc();
			c = '-';
		} else {
			if ((c = xml_getc()) == EOF) return NULL;
			if (c != '>') {
				xml_ungetc();
				xml_ungetc();
				c = '-';
			} else {
				tok_putc('-');
				tok_putc('>');
				tok_putc(0);
				return context->token;
			}
		}
	}

	if (c == '?') { // fetch specials, e.g. '?>'
		if ((c = xml_getc()) == EOF) return NULL;
		if (c != '>') {
			xml_ungetc();
			c = '?';
		} else {
			tok_putc('>');
			tok_putc(0);
			return context->token;
		}
	}

	if (c == '/') {
		if ((c = xml_getc()) == EOF) return NULL;
		if (c == '>') {
			tok_putc(c);
			tok_putc(0);
			return context->token;
		} else return NULL; // syntax error
	}

	if (c == '=' || c == '>') {
		tok_putc(0);
		return context->token;
	}

	if (c == '\"' || c == '\'') { // read in quoted value
		int quote = c;

		context->token_len = 0;

		while ((c = xml_getc()) != EOF) {
			if (c == '&') {
				static const char *aa[] = {"amp", "lt", "gt", "quot", "apos"}, aach[] = "&<>\"'";
				size_t aapos, it;
				int aafound = 0, aasemicolon = 0;
				char aabuf[8];

				for (aapos = 0; aapos<sizeof(aabuf) - 1 && (aabuf[aapos] = xml_getc()) != ';'; aapos++);
				if (aapos<sizeof(aabuf) - 1 && aabuf[aapos] == ';') {
					aasemicolon = 1;
					aabuf[aapos] = 0;

					// TODO: http://www.w3.org/TR/xml/#syntax
					// Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
					if (sscanf(aabuf, "#x%x", (unsigned int *)&c) == 1) { // Hexadecimal
						tok_putc(c);
						aafound = 1;
					} else {
						for (it = 0; it<sizeof(aa) / sizeof(aa[0]); it++)
							if (!strcmp(aabuf, aa[it])) {
								tok_putc(aach[it]);
								aafound = 1;
								break;
							}
					}
				}
				if (!aafound) { // Entity not found: Take data as it is
					if (aapos) {
						// snprintf(buf,sizeof(buf),"&%*s%s",aapos,aabuf,aasemicolon ? ";":"");
						tok_putc('&');
						tok_putmem(aabuf, aapos);
//						for (it = 0; it < aapos; it++)
//							tok_putc(aabuf[it]);
						if (aasemicolon)
							tok_putc(';');
					} else if (aapos == 0) // EOF after "&"
						tok_putc('&');
				}
			} else if (c == quote)
				break;
			else
				tok_putc(c);
		}
		if (c == EOF) return NULL;

		tok_putc(0);
		return context->token;
	}

	if (c == '_' || isalpha(c)) {
		while ((c = xml_getc()) != EOF && !isspace(c) && c != '>' && c != '=')
			tok_putc(c);
		if (c == EOF) return NULL;
		if (c == '>' || c == '=') xml_ungetc();
		tok_putc(0);
		return context->token;
	}

	while ((c = xml_getc()) != EOF && !isspace(c))
		tok_putc(c);

	if (*context->token) {
		xml_ungetc();
		tok_putc(0);
		return context->token;
	}

	return NULL;
}

static int getValue(XML_CONTEXT *context)
{
	int c;

	context->token_len = 0;

	// remove leading spaces
	while ((c = xml_getc()) != EOF && isspace(c));
	if (c == EOF) return EOF;

	tok_putc(c);

	if (c == '=') {
		if (getToken(context) == NULL)
			return EOF;
		else
			return 1; // token valid
	}

	// attribute without value
	tok_putc(0);
	xml_ungetc();
	return 0;
}

// special HTML <script> content parsing
// see http://www.whatwg.org/specs/web-apps/current-work/multipage/scripting-1.html#the-script-element
// 4.3.1.2 Restrictions for contents of script elements

static char *getScriptContent(XML_CONTEXT *context)
{
	int c, comment = 0;
	const char *p;

	context->token_len = 0;

	while ((c = xml_getc()) != EOF) {
		tok_putc(c);

		// we can't use p++ since tok_putc() changes context->token and context->token_len
		p = context->token + context->token_len - 1;

		if (comment) {
			if (*p == '>' && context->token_len >= 3 && !strncmp(context->token + context->token_len - 3, "-->", 3)) {
				comment = 0;
			}
		} else {
			if (*p == '-') {
				if (context->token_len >= 4 && !strncmp(context->token + context->token_len - 4, "<!--", 4)) {
					comment = 1;
				}
			} else if (*p == '>' && context->token_len >= 9) {
				// check if we found </script>
				const char *p2 = p - 1;

				// go back all spaces that may be between '</script' and '>'
				while (isspace(*p2) && p2 >= context->token + 8) p2--;

				if (!strncasecmp(p2 - 7, "</script", 8)) {
					context->token_len -= p - p2 + 8;
					break;
				}
			}
		}
	}

	if (context->token)
		context->token[context->token_len] = 0;

	if (c == EOF) {
		if (context->token_len == 0)
			return NULL;
	}

	if (context->callback)
		context->callback(context->user_ctx, XML_FLG_CONTENT | XML_FLG_END, "script", NULL, context->token);

	return context->token;
}

static char *getUnparsed(XML_CONTEXT *context, int flags, const char *end, size_t len, const char *directory)
{
	int c;

	context->token_len = 0;

	while ((c = xml_getc()) != EOF) {
		tok_putc(c);
		if (context->token_len >= len && !strncmp(context->token + context->token_len - len, end, len)) {
			context->token_len -= len;
			break;
		}
	}

	if (context->token)
		context->token[context->token_len] = 0;

	if (c == EOF) {
		if (context->token_len == 0)
			return NULL;
	}

	if (context->token && context->token_len && context->hints & XML_HINT_REMOVE_EMPTY_CONTENT) {
		int notempty = 0;
		char *p;

		for (p = context->token; *p; p++) {
			if (!isspace(*p)) {
				notempty = 1;
				break;
			}
		}

		if (notempty) {
			if (context->callback)
				context->callback(context->user_ctx, flags, directory, NULL, context->token);
		} else {
			// ignore empty content
			context->token_len = 0;
			context->token[0] = 0;
		}
	} else {
		if (context->callback)
			context->callback(context->user_ctx, flags, directory, NULL, context->token);
	}

	return context->token;
}

static char *getComment(XML_CONTEXT *context)
{
	return getUnparsed(context, XML_FLG_COMMENT, "-->", 3, NULL);
}

static char *getProcessing(XML_CONTEXT *context)
{
	return getUnparsed(context, XML_FLG_PROCESSING, "?>", 2, NULL);
}

static char *getSpecial(XML_CONTEXT *context)
{
	return getUnparsed(context, XML_FLG_SPECIAL, ">", 1, NULL);
}

static char *getContent(XML_CONTEXT *context, const char *directory)
{
	char *p = getUnparsed(context, XML_FLG_CONTENT, "<", 1, directory);
	if (p)
		xml_ungetc();
	return p;
}

#undef tok_putc
#undef tok_putmem
#undef xml_getc
#undef xml_ungetc

static void parseXML(const char *dir, XML_CONTEXT *context)
{
	char directory[256] = "", attribute[64] = "", *tok;
	size_t pos = 0;

	if (!(context->hints & XML_HINT_HTML)) {
		pos = strlcpy(directory, dir, sizeof(directory));
		if (pos >= sizeof(directory)) pos = sizeof(directory) - 1;
	}

	do {
		getContent(context, directory);
		if (context->token_len)
			debug_printf("%s=%s\n", directory, context->token);

		if (!(tok = getToken(context))) return;
		// log_printf("A Token '%s'\n",tok);

		if (!strcmp(tok, "<")) {
			// get element name and add it to directory
			int flags = XML_FLG_BEGIN;

			if (!(tok = getToken(context))) return;
			if (!(context->hints & XML_HINT_HTML)) {
				if (!pos || directory[pos - 1] != '/')
					snprintf(&directory[pos], sizeof(directory) - pos, "/%s", tok);
				else
					strlcpy(&directory[pos], tok, sizeof(directory) - pos);
			} else
				strlcpy(directory, tok, sizeof(directory));

			while ((tok = getToken(context))) {
				// log_printf("C Token %s\n",tok);
				if (!strcmp(tok, "/>")) {
					if (context->callback)
						context->callback(context->user_ctx, flags | XML_FLG_END, directory, NULL, NULL);
					break; // stay in this level
				} else if (!strcmp(tok, ">")) {
					if (context->callback)
						context->callback(context->user_ctx, flags | XML_FLG_CLOSE, directory, NULL, NULL);
					if (context->hints & XML_HINT_HTML) {
						if (!strcasecmp(directory, "script")) {
							// special HTML <script> content parsing
							// see http://www.whatwg.org/specs/web-apps/current-work/multipage/scripting-1.html#the-script-element
							// 4.3.1.2 Restrictions for contents of script elements
							debug_printf("*** need special <script> handling\n");
							getScriptContent(context);
							if (*context->token)
								debug_printf("%s=%s\n", directory, context->token);
						}
					} else
						parseXML(directory, context); // descend one level
					break;
				} else {
					strlcpy(attribute, tok, sizeof(attribute));
					int rc = getValue(context);
					if (rc == EOF) return;
					if (rc) {
						debug_printf("%s/@%s=%s\n", directory, attribute, context->token);
						if (context->callback)
							context->callback(context->user_ctx, flags | XML_FLG_ATTRIBUTE, directory, attribute, context->token);
					} else {
						debug_printf("%s/@%s\n", directory, attribute);
						if (context->callback)
							context->callback(context->user_ctx, flags | XML_FLG_ATTRIBUTE, directory, attribute, NULL);
					}
					flags = 0;
				}
			}
			directory[pos] = 0;
		} else if (!strcmp(tok, "</")) {
			// ascend one level
			// cleanup - get name and '>'
			if (!(tok = getToken(context))) return;
			// log_printf("X Token %s\n",tok);
			if (context->callback) {
				if (!(context->hints & XML_HINT_HTML))
					context->callback(context->user_ctx, XML_FLG_END, directory, NULL, NULL);
				else
					context->callback(context->user_ctx, XML_FLG_END, tok, NULL, NULL);
			}
			if (!(tok = getToken(context))) return;
			// log_printf("Y Token %s\n",tok);
			if (!(context->hints & XML_HINT_HTML))
				return;
			else
				continue;
		} else if (!strcmp(tok, "<!--")) { // comment - ignore
			getComment(context);
			debug_printf("%s=<!--%s-->\n", directory, context->token);
			continue;
		} else if (!strcmp(tok, "<?")) { // special info - ignore
			getProcessing(context);
			debug_printf("%s=<?%s?>\n", directory, context->token);
			continue;
		} else if (!strcmp(tok, "<!")) {
			getSpecial(context);
			debug_printf("%s=<!%s>\n", directory, context->token);
		}
	} while (tok);
}

static int xml_parse_buffer_getc(XML_CONTEXT *context)
{
	if (*context->p)
		return *context->p++;

	return EOF;
}

static void xml_parse_buffer_ungetc(XML_CONTEXT *context)
{
	if (context->p != context->buf)
		context->p--;
}

void xml_parse_buffer(
	const char *buf,
	void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *val),
	void *user_ctx,
	int hints)
{
	XML_CONTEXT context;

	context.token = NULL;
	context.token_size = 0;
	context.token_len = 0;
	context.buf = buf;
	context.p = buf;
	context.fp = NULL;
	context.xml_getc = xml_parse_buffer_getc;
	context.xml_ungetc = xml_parse_buffer_ungetc;
	context.user_ctx = user_ctx;
	context.callback = callback;
	context.hints = hints;

	parseXML("/", &context);
	xfree(context.token);
}

void html_parse_buffer(
	const char *buf,
	void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *val),
	void *user_ctx,
	int hints)
{
	xml_parse_buffer(buf, callback, user_ctx, hints | XML_HINT_HTML);
}

static int xml_parse_file_getc(XML_CONTEXT *context)
{
	return fgetc(context->fp);
}

static void xml_parse_file_ungetc(XML_CONTEXT *context)
{
	fseek(context->fp, -1, SEEK_CUR);
}

void xml_parse_file(
	const char *fname,
	void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *val),
	void *user_ctx,
	int hints)
{
	FILE *fp;
	XML_CONTEXT context;

	// we could also use mmap() and call xml_parse_buffer
	if ((fp = fopen(fname, "r")) != NULL) {
		context.token = NULL;
		context.token_size = 0;
		context.token_len = 0;
		context.buf = NULL;
		context.p = NULL;
		context.fp = fp;
		context.xml_getc = xml_parse_file_getc;
		context.xml_ungetc = xml_parse_file_ungetc;
		context.user_ctx = user_ctx;
		context.callback = callback;
		context.hints = hints;

		parseXML("/", &context);
		xfree(context.token);

		fclose(fp);
	} else
		error_printf(_("%s: Failed to open %s\n"), __func__, fname);
}

void html_parse_file(
	const char *fname,
	void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *val),
	void *user_ctx,
	int hints)
{
	xml_parse_file(fname, callback, user_ctx, hints | XML_HINT_HTML);
}

/*
// version with nested functions, much clearer... sigh
void xml_parse_buffer(const char *buf, void(*callback)(char *, char *, char *))
{
	const char *p = buf;

	void my_ungetc(void) { if (p != buf) p--; }
	int my_getc(void) { return *p ? *p++ : EOF; }

	parseXML("", callback, my_getc, my_ungetc);
}

// version with nested functions, much clearer... sigh
void xml_parse_file(const char *fname, void(*callback)(char *, char *, char *))
{
	FILE	*fp;

	void my_ungetc(void) { fseek(fp, -1, SEEK_CUR); }
	int my_getc(void) { return fgetc(fp); }

	if ((fp = fopen(fname, "r")) != NULL) {
		parseXML("", callback, my_getc, my_ungetc);
		fclose(fp);
	} else err_printf(_("%s: Failed to open %s\n"), __func__, fname);
}
 */

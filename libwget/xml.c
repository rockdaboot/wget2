/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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
 * https://html.spec.whatwg.org/multipage/syntax.html
 * It is a PITA and should be handled by a specialized, external library !
 *
 */

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#include <wget.h>
#include "private.h"

typedef struct {
	const char
		*buf, // pointer to original start of buffer (0-terminated)
		*p, // pointer next char in buffer
		*token; // token buffer
	int
		hints; // XML_HINT...
	size_t
		token_size, // size of token buffer
		token_len; // used bytes of token buffer (not counting terminating 0 byte)
	void
		*user_ctx; // user context (not needed if we were using nested functions)
	wget_xml_callback
		*callback;
} _xml_context;

/* \cond _hide_internal_symbols */
#define ascii_isspace(c) (c == ' ' || (c >= 9 && c <=  13))

// working only for consecutive alphabets, e.g. EBCDIC would not work
#define ascii_isalpha(c) ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
/* \endcond */

// append a char to token buffer

static const char *getToken(_xml_context *context)
{
	int c;
	const char *p;

	// skip leading whitespace
	while ((c = *context->p) && ascii_isspace(c))
		context->p++;
	if (!c) return NULL; // eof
	context->token = context->p++;

//	info_printf("a c=%c\n", c);

	if (ascii_isalpha(c) || c == '_') {
		while ((c = *context->p) && !ascii_isspace(c) && c != '>' && c != '=')
			context->p++;
		if (!c) return NULL; // syntax error

		context->token_len = context->p - context->token;
		return context->token;
	}

	if (c == '/') {
		if (!(c = *context->p)) return NULL; // syntax error
		context->p++;
		if (c == '>') {
			context->token_len = 2;
			return context->token;
		} else return NULL; // syntax error
	}

	if (c == '\"' || c == '\'') { // read in quoted value
		int quote = c;

		context->token = context->p;

		if (!(p = strchr(context->p, quote)))
			return NULL;
		context->p = p + 1;

		context->token_len = context->p - context->token - 1;
		return context->token;
	}

	if (c == '<') { // fetch specials, e.g. start of comments '<!--'
		if (!(c = *context->p)) return NULL; // syntax error
		context->p++;
		if (c == '?' || c == '/') {
			context->token_len = 2;
			return context->token;
		}

		if (c == '!') {
			// left: <!--, <![CDATA[ and <!WHATEVER
			if (!(c = *context->p)) return NULL; // syntax error
			if (c == '-') {
				context->p++;
				if (!(c = *context->p)) return NULL; // syntax error
				context->p++;
				if (c == '-') {
					context->token_len = 4;
					return context->token;
				} else {
					context->p -= 2;
					context->token_len = 2;
					return context->token;
				}
			} else {
				context->token_len = 2;
				return context->token;
			}
		} else {
			context->p--;
			context->token_len = 1;
			return context->token;
		}
	}

	if (c == '>' || c == '=') {
		context->token_len = 1;
		return context->token;
	}

	if (c == '-') { // fetch specials, e.g. end of comments '-->'
		if (!(c = *context->p)) return NULL; // syntax error
		if (c != '-') {
			c = '-';  //???
		} else {
			context->p++;
			if (!(c = *context->p)) return NULL; // syntax error
			context->p++;
			if (c != '>') {
				context->p -= 2;
				c = '-';
			} else {
				context->token_len = 3;
				return context->token;
			}
		}
	}

	if (c == '?') { // fetch specials, e.g. '?>'
		if (!(c = *context->p)) return NULL; // syntax error
		if (c != '>') {
			// c = '?';
		} else {
			context->p++;
			context->token_len = 2;
			return context->token;
		}
	}

	while ((c = *context->p) && !ascii_isspace(c))
		context->p++;

	if (c) {
		context->token_len = context->p - context->token;
		return context->token;
	}

	return NULL;
}

static int getValue(_xml_context *context)
{
	int c;

	context->token_len = 0;
	context->token = context->p;

	// remove leading spaces
	while ((c = *context->p) && ascii_isspace(c))
		context->p++;
	if (!c) return EOF;

	if (c == '=') {
		context->p++;
		if (!getToken(context))
			return EOF; // syntax error
		else
			return 1; // token valid
	}

	// attribute without value
	context->token = context->p;
	return 1;
}

// special HTML <script> content parsing
// see https://html.spec.whatwg.org/multipage/scripting.html#the-script-element
// 4.3.1.2 Restrictions for contents of script elements

static const char *getScriptContent(_xml_context *context)
{
	int comment = 0, length_valid = 0;
	const char *p;

	for (p = context->token = context->p; *p; p++) {
		if (comment) {
			if (*p == '-' && !strncmp(p, "-->", 3)) {
				p += 3 - 1;
				comment = 0;
			}
		} else {
			if (*p == '<' && !strncmp(p, "<!--", 4)) {
				p += 4 - 1;
				comment = 1;
			} else if (*p == '<' && !wget_strncasecmp_ascii(p, "</script", 8)) {
				context->token_len = p - context->token;
				length_valid = 1;
				for (p += 8; ascii_isspace(*p); p++);
				if (*p == '>') {
					p++;
					break; // found end of <script>
				} else if (!*p)
					break; // end of input
			}
		}
	}
	context->p = p;

	if (!length_valid)
		context->token_len = p - context->token;

	if (!*p && !context->token_len)
		return NULL;

	if (context->callback)
		context->callback(context->user_ctx, XML_FLG_CONTENT | XML_FLG_END, "script", NULL, context->token, context->token_len, context->token - context->buf);

	return context->token;
}

static const char *getUnparsed(_xml_context *context, int flags, const char *end, size_t len, const char *directory)
{
	int c;

	if (len == 1) {
		for (context->token = context->p; (c = *context->p) && c != *end; context->p++);
	} else {
		for (context->token = context->p; (c = *context->p); context->p++) {
			if (c == *end && context->p[1] == end[1] && (len == 2 || context->p[2] == end[2])) {
				break;
			}
		}
	}

	context->token_len = context->p - context->token;
	if (c) context->p += len;

	if (!c && !context->token_len)
		return NULL;
/*
	if (context->token && context->token_len && context->hints & XML_HINT_REMOVE_EMPTY_CONTENT) {
		int notempty = 0;
		char *p;

		for (p = context->token; *p; p++) {
			if (!ascii_isspace(*p)) {
				notempty = 1;
				break;
			}
		}

		if (notempty) {
			if (context->callback)
				context->callback(context->user_ctx, flags, directory, NULL, context->token, context->token_len, context->token - context->buf);
		} else {
			// ignore empty content
			context->token_len = 0;
			context->token[0] = 0;
		}
	} else {
*/
	if (context->callback)
		context->callback(context->user_ctx, flags, directory, NULL, context->token, context->token_len, context->token - context->buf);

//	}

	return context->token;
}

static const char *getComment(_xml_context *context)
{
	return getUnparsed(context, XML_FLG_COMMENT, "-->", 3, NULL);
}

static const char *getProcessing(_xml_context *context)
{
	return getUnparsed(context, XML_FLG_PROCESSING, "?>", 2, NULL);
}

static const char *getSpecial(_xml_context *context)
{
	return getUnparsed(context, XML_FLG_SPECIAL, ">", 1, NULL);
}

static const char *getContent(_xml_context *context, const char *directory)
{
	int c;

		for (context->token = context->p; (c = *context->p) && c != '<'; context->p++);

	context->token_len = context->p - context->token;

	if (!c && !context->token_len)
		return NULL;

	// debug_printf("content=%.*s\n", (int)context->token_len, context->token);
	if (context->callback && context->token_len)
		context->callback(context->user_ctx, XML_FLG_CONTENT, directory, NULL, context->token, context->token_len, context->token - context->buf);

	return context->token;
}

static int parseXML(const char *dir, _xml_context *context)
{
	const char *tok;
	char directory[256] = "";
	size_t pos = 0;

	if (!(context->hints & XML_HINT_HTML)) {
		pos = wget_strlcpy(directory, dir, sizeof(directory));
		if (pos >= sizeof(directory)) pos = sizeof(directory) - 1;
	}

	do {
		getContent(context, directory);
		if (context->token_len)
			debug_printf("%s='%.*s'\n", directory, (int)context->token_len, context->token);

		if (!(tok = getToken(context))) return WGET_E_SUCCESS;  //eof
		// debug_printf("A Token '%.*s' len=%zu tok='%s'\n", (int)context->token_len, context->token, context->token_len, tok);

		if (context->token_len == 1 && *tok == '<') {
			// get element name and add it to directory
			int flags = XML_FLG_BEGIN;

			if (!(tok = getToken(context))) return WGET_E_XML_PARSE_ERR; // syntax error

			// debug_printf("A2 Token '%.*s'\n", (int)context->token_len, context->token);

			if (!(context->hints & XML_HINT_HTML)) {
				if (!pos || directory[pos - 1] != '/')
					wget_snprintf(&directory[pos], sizeof(directory) - pos, "/%.*s", (int)context->token_len, tok);
				else
					wget_snprintf(&directory[pos], sizeof(directory) - pos, "%.*s", (int)context->token_len, tok);
			} else {
				// wget_snprintf(directory, sizeof(directory), "%.*s", (int)context->token_len, tok);
				if (context->token_len < sizeof(directory)) {
					memcpy(directory, tok, context->token_len);
					directory[context->token_len] = 0;
				} else {
					memcpy(directory, tok, sizeof(directory) - 1);
					directory[sizeof(directory) - 1] = 0;
				}
			}

			while ((tok = getToken(context))) {
				// debug_printf("C Token %.*s %zu %p %p dir=%s tok=%s\n", (int)context->token_len, context->token, context->token_len, context->token, context->p, directory, tok);
				if (context->token_len == 2 && !strncmp(tok, "/>", 2)) {
					if (context->callback)
						context->callback(context->user_ctx, flags | XML_FLG_END, directory, NULL, NULL, 0, 0);
					break; // stay in this level
				} else if (context->token_len == 1 && *tok == '>') {
					if (context->callback)
						context->callback(context->user_ctx, flags | XML_FLG_CLOSE, directory, NULL, NULL, 0, 0);
					if (context->hints & XML_HINT_HTML) {
						if (!wget_strcasecmp_ascii(directory, "script")) {
							// special HTML <script> content parsing
							// see https://html.spec.whatwg.org/multipage/scripting.html#the-script-element
							// 4.3.1.2 Restrictions for contents of script elements
							debug_printf("*** need special <script> handling\n");
							getScriptContent(context);
							if (context->token_len)
								debug_printf("%s=%.*s\n", directory, (int)context->token_len, context->token);
						}
						else if (!wget_strcasecmp_ascii(directory, "style")) {
							getContent(context, "style");
							if (context->token_len)
								debug_printf("%s=%.*s\n", directory, (int)context->token_len, context->token);
						}
					} else
						parseXML(directory, context); // descend one level
					break;
				} else {
//					wget_snprintf(attribute, sizeof(attribute), "%.*s", (int)context->token_len, tok);
					char attribute[context->token_len + 1];
					memcpy(attribute, tok, context->token_len);
					attribute[context->token_len] = 0;

					if (getValue(context) == EOF) return WGET_E_XML_PARSE_ERR; // syntax error

					if (context->token_len) {
						debug_printf("%s/@%s=%.*s\n", directory, attribute, (int)context->token_len, context->token);
						if (context->callback)
							context->callback(context->user_ctx, flags | XML_FLG_ATTRIBUTE, directory, attribute, context->token, context->token_len, context->token - context->buf);
					} else {
						debug_printf("%s/@%s\n", directory, attribute);
						if (context->callback)
							context->callback(context->user_ctx, flags | XML_FLG_ATTRIBUTE, directory, attribute, NULL, 0, 0);
					}
					flags = 0;
				}
			}
			directory[pos] = 0;
		} else if (context->token_len == 2) {
			if (!strncmp(tok, "</", 2)) {
				// ascend one level
				// cleanup - get name and '>'
				if (!(tok = getToken(context))) return WGET_E_XML_PARSE_ERR;
				// debug_printf("X Token %s\n",tok);
				if (context->callback) {
					if (!(context->hints & XML_HINT_HTML))
						context->callback(context->user_ctx, XML_FLG_END, directory, NULL, NULL, 0, 0);
					else {
						char tag[context->token_len + 1]; // we need to \0 terminate tok
						memcpy(tag, tok, context->token_len);
						tag[context->token_len] = 0;
						context->callback(context->user_ctx, XML_FLG_END, tag, NULL, NULL, 0, 0);
					}
				}
				if (!(tok = getToken(context))) return WGET_E_XML_PARSE_ERR;
				// debug_printf("Y Token %s\n",tok);
				if (!(context->hints & XML_HINT_HTML))
					return WGET_E_SUCCESS;
				else
					continue;
			} else if (!strncmp(tok, "<?", 2)) { // special info - ignore
				getProcessing(context);
				debug_printf("%s=<?%.*s?>\n", directory, (int)context->token_len, context->token);
				continue;
			} else if (!strncmp(tok, "<!", 2)) {
				getSpecial(context);
				debug_printf("%s=<!%.*s>\n", directory, (int)context->token_len, context->token);
			}
		} else if (context->token_len == 4 && !strncmp(tok, "<!--", 4)) { // comment - ignore
			getComment(context);
			debug_printf("%s=<!--%.*s-->\n", directory, (int)context->token_len, context->token);
			continue;
		}
	} while (tok);
	return WGET_E_SUCCESS;
}

/**
 * \file
 * \brief XML parsing functions
 * \defgroup libwget-xml XML parsing functions
 * @{
 */

/**
 * \param[in] buf Zero-terminated XML or HTML input data
 * \param[in] callback Function called for each token scan result
 * \param[in] user_ctx User-defined context variable, handed to \p callback
 * \param[in] hints Flags to influence parsing
 *
 * This function scans the XML input from \p buf and calls \p callback for each token
 * found. \p user_ctx is a user-defined context variable and given to each call of \p callback.
 *
 * \p hints may be 0 or any combination of %XML_HINT_REMOVE_EMPTY_CONTENT and %XML_HINT_HTML.
 *
 * %XML_HINT_REMOVE_EMPTY_CONTENT reduces the number of calls to \p callback by ignoring
 * empty content and superfluous spaces.
 *
 * %XML_HINT_HTML turns on HTML scanning.
 */
int wget_xml_parse_buffer(
	const char *buf,
	wget_xml_callback *callback,
	void *user_ctx,
	int hints)
{
	_xml_context context;

	context.token = NULL;
	context.token_size = 0;
	context.token_len = 0;
	context.buf = buf;
	context.p = buf;
	context.user_ctx = user_ctx;
	context.callback = callback;
	context.hints = hints;

	return parseXML ("/", &context);
}

/**
 * \param[in] buf Zero-terminated HTML input data
 * \param[in] callback Function called for each token scan result
 * \param[in] user_ctx User-defined context variable, handed to \p callback
 * \param[in] hints Flags to influence parsing
 *
 * Convenience function that calls wget_xml_parse_buffer() with HTML parsing turned on.
 */
void wget_html_parse_buffer(
	const char *buf,
	wget_xml_callback *callback,
	void *user_ctx,
	int hints)
{
	wget_xml_parse_buffer(buf, callback, user_ctx, hints | XML_HINT_HTML);
}

/**
 * \param[in] fname Name of XML or HTML input file
 * \param[in] callback Function called for each token scan result
 * \param[in] user_ctx User-defined context variable, handed to \p callback
 * \param[in] hints Flags to influence parsing
 *
 * Convenience function that calls wget_xml_parse_buffer() with the file content.
 *
 * If \p fname is `-`, the data is read from stdin.
 */
void wget_xml_parse_file(
	const char *fname,
	wget_xml_callback *callback,
	void *user_ctx,
	int hints)
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
				char *buf=wget_malloc(st.st_size + 1);
				size_t nread=read(fd, buf, st.st_size);
#endif

				if (nread > 0) {
					buf[nread] = 0; // PROT_WRITE allows this write, MAP_PRIVATE prevents changes in underlying file system
					wget_xml_parse_buffer(buf, callback, user_ctx, hints);
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
			wget_xml_parse_buffer(buf.data, callback, user_ctx, hints);

		wget_buffer_deinit(&buf);
	}
}

/**
 * \param[in] fname Name of XML or HTML input file
 * \param[in] callback Function called for each token scan result
 * \param[in] user_ctx User-defined context variable, handed to \p callback
 * \param[in] hints Flags to influence parsing
 *
 * Convenience function that calls wget_xml_parse_file() with HTML parsing turned on.
 *
 * If \p fname is `-`, the data is read from stdin.
 */
void wget_html_parse_file(
	const char *fname,
	wget_xml_callback *callback,
	void *user_ctx,
	int hints)
{
	wget_xml_parse_file(fname, callback, user_ctx, hints | XML_HINT_HTML);
}

/** @} */

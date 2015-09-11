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
 * Extracting URLs from HTML
 *
 * Changelog
 * 26.09.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libmget.h>
#include "private.h"

typedef struct {
	MGET_HTML_PARSED_RESULT
		result;
	mget_vector_t *
		additional_tags;
	mget_vector_t *
		ignore_tags;
	char
		found_robots,
		found_content_type;
} _html_context_t;

// see http://stackoverflow.com/questions/2725156/complete-list-of-html-tag-attributes-which-have-a-url-value
static const char maybe[256] = {
	['a'] = 1,
	['b'] = 1,
	['c'] = 1,
	['d'] = 1,
	['f'] = 1,
	['h'] = 1,
	['i'] = 1,
	['l'] = 1,
	['m'] = 1,
	['p'] = 1,
	['s'] = 1,
	['u'] = 1,
};
static const char attrs[][12] = {
	"action", "archive",
	"background",
	"code", "codebase", "cite", "classid",
	"data",
	"formaction",
	"href",
	"icon",
	"lowsrc", "longdesc",
	"manifest",
	"profile", "poster",
	"src",
	"usemap"
};

// Callback function, called from HTML parser for each URI found.
static void _html_get_url(void *context, int flags, const char *tag, const char *attr, const char *val, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	_html_context_t *ctx = context;

	// Read the encoding from META tag, e.g. from
	//   <meta http-equiv="Content-Type" content="text/html; charset=utf-8">.
	// It overrides the encoding from the HTTP response resp. from the CLI.
	//
	// Also ,we are interested in ROBOTS e.g.
	//   <META name="ROBOTS" content="NOINDEX, NOFOLLOW">
	if ((flags & XML_FLG_BEGIN) && (*tag|0x20) == 'm' && !mget_strcasecmp_ascii(tag, "meta")) {
		ctx->found_robots = ctx->found_content_type = 0;
	}

	if ((flags & XML_FLG_ATTRIBUTE) && val) {
		MGET_HTML_PARSED_RESULT *res = &ctx->result;

//		info_printf("%02X %s %s '%.*s' %zd %zd\n", flags, dir, attr, (int) len, val, len, pos);

		if ((*tag|0x20) == 'm' && !mget_strcasecmp_ascii(tag, "meta")) {
			if (!ctx->found_robots) {
				if (!mget_strcasecmp_ascii(attr, "name") && !mget_strncasecmp_ascii(val, "robots", len)) {
					ctx->found_robots = 1;
					return;
				}
			} else if (ctx->found_robots && !mget_strcasecmp_ascii(attr, "content")) {
				char *p;
				char valbuf[len + 1], *value = valbuf;

				memcpy(value, val, len);
				value[len] = 0;

				while (*value) {
					while (isspace(*value)) value++;
					if (*value == ',') { value++; continue; }
					for (p = value; *p && !isspace(*p) && *p != ','; p++);
					if (p == value) break;

					// debug_printf("ROBOTS='%.*s'\n", (int)(p - value), value);
					if (!strncasecmp(value, "all", p - value) || !strncasecmp(value, "follow", p - value))
						res->follow = 1;
					else if (!strncasecmp(value, "nofollow", p - value) || !strncasecmp(value, "none", p - value))
						res->follow = 0;

					value = *p  ? p + 1 : p;
				}
				return;
			}

			if (ctx->found_content_type && !res->encoding) {
				if (!mget_strcasecmp_ascii(attr, "content")) {
					char valbuf[len + 1], *value = valbuf;

					memcpy(value, val, len);
					value[len] = 0;
					mget_http_parse_content_type(value, NULL, &res->encoding);
				}
			}
			else if (!ctx->found_content_type && !res->encoding) {
				if (!mget_strcasecmp_ascii(attr, "http-equiv") && !mget_strncasecmp_ascii(val, "Content-Type", len)) {
					ctx->found_content_type = 1;
				}
				else if (!mget_strcasecmp_ascii(attr, "charset")) {
					res->encoding = mget_strmemdup(val, len);
				}
			}

			return;
		}

		if (ctx->ignore_tags) {
			if (mget_vector_find(ctx->ignore_tags, &(mget_html_tag_t){ .name = tag, .attribute = NULL } ) != -1
				|| mget_vector_find(ctx->ignore_tags, &(mget_html_tag_t){ .name = tag, .attribute = attr } ) != -1)
				return;
		}

		// shortcut to avoid unneeded calls to bsearch()
		int found = 0;

		// search the static list for a tag/attr match
		if (maybe[(unsigned char)*attr|0x20] && attr[1] && attr[2])
			found = bsearch(attr, attrs, countof(attrs), sizeof(attrs[0]), (int(*)(const void *, const void *))mget_strcasecmp_ascii) != NULL;

		// search the dynamic list for a tag/attr match
		if (!found && ctx->additional_tags) {
			if (mget_vector_find(ctx->additional_tags, &(mget_html_tag_t){ .name = tag, .attribute = NULL } ) != -1
				|| mget_vector_find(ctx->additional_tags, &(mget_html_tag_t){ .name = tag, .attribute = attr } ) != -1)
				found = 1;
		}

		if (found) {
			for (;len && isspace(*val); val++, len--); // skip leading spaces
			for (;len && isspace(val[len - 1]); len--);  // skip trailing spaces

			if ((*tag|0x20) == 'b' && !mget_strcasecmp_ascii(tag,"base")) {
				// found a <BASE href="...">
				res->base.p = val;
				res->base.len = len;
				return;
			}

			if (!res->uris)
				res->uris = mget_vector_create(32, -2, NULL);

			MGET_HTML_PARSED_URL url;
			strlcpy(url.attr, attr, sizeof(url.attr));
			strlcpy(url.dir, tag, sizeof(url.dir));
			url.url.p = val;
			url.url.len = len;
			mget_vector_add(res->uris, &url, sizeof(url));
		}
	}
}

/*
static void _urls_to_absolute(MGET_VECTOR *urls, MGET_IRI *base)
{
	if (base && urls) {
		mget_buffer_t buf;
		mget_buffer_init(&buf, NULL, 1024);

		for (int it = 0; it < mget_vector_size(urls); it++) {
			MGET_PARSED_URL *url = mget_vector_get(urls, it);

			if (mget_iri_relative_to_abs(base, url->url, url->len, &buf))
				url->abs_url = strndup(buf.data, buf.length + 1);
			else
				error_printf("Cannot resolve relative URI '%s'\n", url->url);
		}

		mget_buffer_deinit(&buf);
	}
}
*/

void mget_html_free_urls_inline (MGET_HTML_PARSED_RESULT **res)
{
	if (res && *res) {
		xfree((*res)->encoding);
		mget_vector_free(&(*res)->uris);
		xfree(*res);
	}
}

MGET_HTML_PARSED_RESULT *mget_html_get_urls_inline(const char *html, mget_vector_t *additional_tags, mget_vector_t *ignore_tags)
{
	_html_context_t context = {
		.result.follow = 1,
		.additional_tags = additional_tags,
		.ignore_tags = ignore_tags
	};

//	context.result.uris = mget_vector_create(32, -2, NULL);
	mget_html_parse_buffer(html, _html_get_url, &context, HTML_HINT_REMOVE_EMPTY_CONTENT);

	return mget_memdup(&context.result, sizeof(context.result));
}

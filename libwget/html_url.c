/*
 * Copyright(c) 2013 Tim Ruehsen
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
 * Extracting URLs from HTML
 *
 * Changelog
 * 26.09.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <c-ctype.h>

#include <wget.h>
#include "private.h"

typedef struct {
	wget_html_parsed_result
		result;
	wget_vector *
		additional_tags;
	wget_vector *
		ignore_tags;
	int
		uri_index;
	size_t
		css_start_offset;
	char
		found_robots,
		found_content_type,
		link_inline;
	const char
		* html,
		* css_attr,
		* css_dir;
} _html_context_t;

// see https://stackoverflow.com/questions/2725156/complete-list-of-html-tag-attributes-which-have-a-url-value
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
	"src", "srcset",
	"usemap"
};

static void _css_parse_uri(void *context, const char *url WGET_GCC_UNUSED, size_t len, size_t pos)
{
	_html_context_t *ctx = context;
	wget_html_parsed_result *res = &ctx->result;
	wget_html_parsed_url *parsed_url;

	if (!(parsed_url = wget_malloc(sizeof(wget_html_parsed_url))))
		return;

	parsed_url->link_inline = 1;
	wget_strscpy(parsed_url->attr, ctx->css_attr, sizeof(parsed_url->attr));
	wget_strscpy(parsed_url->dir, ctx->css_dir, sizeof(parsed_url->dir));
	parsed_url->url.p = (const char *) (ctx->html + ctx->css_start_offset + pos);
	parsed_url->url.len = len;

	if (!res->uris)
		res->uris = wget_vector_create(32, NULL);

	wget_vector_add(res->uris, parsed_url);
}

// Callback function, called from HTML parser for each URI found.
static void _html_get_url(void *context, int flags, const char *tag, const char *attr, const char *val, size_t len, size_t pos WGET_GCC_UNUSED)
{
	_html_context_t *ctx = context;

	// Read the encoding from META tag, e.g. from
	//   <meta http-equiv="Content-Type" content="text/html; charset=utf-8">.
	// It overrides the encoding from the HTTP response resp. from the CLI.
	//
	// Also ,we are interested in ROBOTS e.g.
	//   <META name="ROBOTS" content="NOINDEX, NOFOLLOW">
	if ((flags & XML_FLG_BEGIN)) {
		if ((*tag|0x20) == 'm' && !wget_strcasecmp_ascii(tag, "meta"))
			ctx->found_robots = ctx->found_content_type = 0;
		else if ((*tag|0x20) == 'l' && !wget_strcasecmp_ascii(tag, "link")) {
			ctx->link_inline = 0;
			ctx->uri_index = -1;
		}
	}

	if ((flags & XML_FLG_ATTRIBUTE) && val) {
		wget_html_parsed_result *res = &ctx->result;

//		debug_printf("%02X %s %s '%.*s' %zu %zu\n", (unsigned) flags, tag, attr, (int) len, val, len, pos);

		if ((*tag|0x20) == 'm' && !wget_strcasecmp_ascii(tag, "meta")) {
			if (!ctx->found_robots) {
				if (!wget_strcasecmp_ascii(attr, "name") && !wget_strncasecmp_ascii(val, "robots", len)) {
					ctx->found_robots = 1;
					return;
				}
			} else if (ctx->found_robots && !wget_strcasecmp_ascii(attr, "content")) {
				char *p;
				char valbuf[len + 1], *value = valbuf;

				memcpy(value, val, len);
				value[len] = 0;

				while (*value) {
					while (c_isspace(*value)) value++;
					if (*value == ',') { value++; continue; }
					for (p = value; *p && !c_isspace(*p) && *p != ','; p++);
					if (p == value) break;

					// debug_printf("ROBOTS='%.*s'\n", (int)(p - value), value);
					if (!wget_strncasecmp_ascii(value, "all", p - value) || !wget_strncasecmp_ascii(value, "follow", p - value))
						res->follow = 1;
					else if (!wget_strncasecmp_ascii(value, "nofollow", p - value) || !wget_strncasecmp_ascii(value, "none", p - value))
						res->follow = 0;

					value = *p  ? p + 1 : p;
				}
				return;
			}

			if (ctx->found_content_type && !res->encoding) {
				if (!wget_strcasecmp_ascii(attr, "content")) {
					char valbuf[len + 1], *value = valbuf;

					memcpy(value, val, len);
					value[len] = 0;
					wget_http_parse_content_type(value, NULL, &res->encoding);
				}
			}
			else if (!ctx->found_content_type && !res->encoding) {
				if (!wget_strcasecmp_ascii(attr, "http-equiv") && !wget_strncasecmp_ascii(val, "Content-Type", len)) {
					ctx->found_content_type = 1;
				}
				else if (!wget_strcasecmp_ascii(attr, "charset")) {
					res->encoding = wget_strmemdup(val, len);
				}
			}

			return;
		}

		if (ctx->ignore_tags) {
			if (wget_vector_find(ctx->ignore_tags, &(wget_html_tag){ .name = tag, .attribute = NULL } ) != -1
				|| wget_vector_find(ctx->ignore_tags, &(wget_html_tag){ .name = tag, .attribute = attr } ) != -1)
				return;
		}

		if ((*attr|0x20) == 's' && !wget_strcasecmp_ascii(attr, "style") && len) {
			ctx->css_dir = tag;
			ctx->css_attr = "style";
			ctx->css_start_offset = val - ctx->html;
			wget_css_parse_buffer(val, len, _css_parse_uri, NULL, context);
			return;
		}

		if ((*tag|0x20) == 'l' && !wget_strcasecmp_ascii(tag, "link")) {
			if (!wget_strcasecmp_ascii(attr, "rel")) {
				if (!wget_strncasecmp_ascii(val, "shortcut icon", len)
					|| !wget_strncasecmp_ascii(val, "stylesheet", len)
					|| !wget_strncasecmp_ascii(val, "preload", len))
					ctx->link_inline = 1;
				else
					ctx->link_inline = 0;

				if (ctx->uri_index >= 0) {
					// href= came before rel=
					wget_html_parsed_url *url = wget_vector_get(res->uris, ctx->uri_index);
					url->link_inline = ctx->link_inline;
				}
			}
		}

		// shortcut to avoid unneeded calls to bsearch()
		int found = 0;

		// search the static list for a tag/attr match
		if (maybe[(unsigned char)*attr|0x20] && attr[1] && attr[2])
			found = bsearch(attr, attrs, countof(attrs), sizeof(attrs[0]), (int(*)(const void *, const void *))wget_strcasecmp_ascii) != NULL;

		// search the dynamic list for a tag/attr match
		if (!found && ctx->additional_tags) {
			if (wget_vector_find(ctx->additional_tags, &(wget_html_tag){ .name = tag, .attribute = NULL } ) != -1
				|| wget_vector_find(ctx->additional_tags, &(wget_html_tag){ .name = tag, .attribute = attr } ) != -1)
				found = 1;
		}

		if (found) {
			for (;len && c_isspace(*val); val++, len--); // skip leading spaces
			for (;len && c_isspace(val[len - 1]); len--);  // skip trailing spaces

			if ((*tag|0x20) == 'b' && !wget_strcasecmp_ascii(tag, "base")) {
				// found a <BASE href="...">
				res->base.p = val;
				res->base.len = len;
				return;
			}

			if (!res->uris)
				res->uris = wget_vector_create(32, NULL);

			wget_html_parsed_url url;

			if (!wget_strcasecmp_ascii(attr, "srcset")) {
				// value is a list of URLs, see https://html.spec.whatwg.org/multipage/embedded-content.html#attr-img-srcset
				while (len) {
					const char *p;

					for (;len && c_isspace(*val); val++, len--); // skip leading spaces
					for (p = val;len && !c_isspace(*val) && *val != ','; val++, len--); // find end of URL
					if (p != val) {
						url.link_inline = ctx->link_inline;
						wget_strscpy(url.attr, attr, sizeof(url.attr));
						wget_strscpy(url.dir, tag, sizeof(url.dir));
						url.url.p = p;
						url.url.len = val - p;
						wget_vector_add_memdup(res->uris, &url, sizeof(url));
					}
					for (;len && *val != ','; val++, len--); // skip optional width/density descriptor
					if (len && *val == ',') { val++; len--; }
				}

			} else {
				// value is a single URL
				url.link_inline = ctx->link_inline;
				wget_strscpy(url.attr, attr, sizeof(url.attr));
				wget_strscpy(url.dir, tag, sizeof(url.dir));
				url.url.p = val;
				url.url.len = len;
				ctx->uri_index = wget_vector_add_memdup(res->uris, &url, sizeof(url));
			}
		}
	}

	if (flags & XML_FLG_CONTENT && val && len && !wget_strcasecmp_ascii(tag, "style")) {
		ctx->css_dir = "style";
		ctx->css_attr = "";
		ctx->css_start_offset = val - ctx->html;
		wget_css_parse_buffer(val, len, _css_parse_uri, NULL, context);
	}
}

void wget_html_free_urls_inline (wget_html_parsed_result **res)
{
	if (res && *res) {
		xfree((*res)->encoding);
		wget_vector_free(&(*res)->uris);
		xfree(*res);
	}
}

wget_html_parsed_result *wget_html_get_urls_inline(const char *html, wget_vector *additional_tags, wget_vector *ignore_tags)
{
	_html_context_t context = {
		.result.follow = 1,
		.additional_tags = additional_tags,
		.ignore_tags = ignore_tags,
		.html = html,
	};

//	context.result.uris = wget_vector_create(32, -2, NULL);
	wget_html_parse_buffer(html, _html_get_url, &context, HTML_HINT_REMOVE_EMPTY_CONTENT);

	return wget_memdup(&context.result, sizeof(context.result));
}

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
 * IRI/URI routines
 *
 * Changelog
 * 10.07.2012  Tim Ruehsen  created (refactored from mget.c)
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include <libmget.h>

#include "metalink.h"

struct metalink_context {
	int
		sockfd,
		priority;
	char
		hash[128],
		hash_type[16],
		location[8];
	long long
		length;
};

static void _metalink4_parse(void *context, int flags, const char *dir, const char *attr, const char *value)
{
	struct metalink_context *ctx = context;

	// info_printf("\n%02X %s %s '%s'\n", flags, dir, attr, value);
	if (!(flags & (XML_FLG_CONTENT | XML_FLG_ATTRIBUTE))) return; // ignore comments

	if (strncasecmp(dir, "/metalink/file", 14)) return;

	if (attr) {
		if (dir[14] == 0) { // /metalink/file
			if (!strcasecmp(attr, "name")) {
				dprintf(ctx->sockfd, "chunk name %s\n", value);
			}
		} else if (!strcasecmp(dir + 14, "/pieces")) {
			if (!strcasecmp(attr, "type")) {
				sscanf(value, "%15s", ctx->hash_type);
			} else if (!strcasecmp(attr, "length")) {
				ctx->length = atoll(value);
			}
		} else if (!strcasecmp(dir + 14, "/hash")) {
			if (!strcasecmp(attr, "type")) {
				sscanf(value, "%15s", ctx->hash_type);
			}
		} else if (!strcasecmp(dir + 14, "/url")) {
			if (!strcasecmp(attr, "location")) {
				sscanf(value, " %2[a-zA-Z]", ctx->location); // ISO 3166-1 alpha-2 two letter country code
			} else if (!strcasecmp(attr, "priority")) {
				sscanf(value, " %6d", &ctx->priority);
				if (ctx->priority < 1 || ctx->priority > 999999)
					ctx->priority = 999999;
			}
		}
	} else {
		if (!strcasecmp(dir + 14, "/pieces/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (ctx->length && *ctx->hash_type && *ctx->hash)
				dprintf(ctx->sockfd, "chunk piece %lld %s %s\n", ctx->length, ctx->hash_type, ctx->hash);
			*ctx->hash = 0;
		} else if (!strcasecmp(dir + 14, "/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (*ctx->hash_type && *ctx->hash)
				dprintf(ctx->sockfd, "chunk hash %s %s\n", ctx->hash_type, ctx->hash);
			*ctx->hash_type = *ctx->hash = 0;
		} else if (!strcasecmp(dir + 14, "/size")) {
			dprintf(ctx->sockfd, "chunk size %lld\n", atoll(value));
		} else if (!strcasecmp(dir + 14, "/url")) {
			dprintf(ctx->sockfd, "chunk mirror %s %u %s\n", ctx->location, ctx->priority, value);
			strcpy(ctx->location, "-");
			ctx->priority = 999999;
		}
	}
}

void metalink4_parse(int sockfd, MGET_HTTP_RESPONSE *resp)
{
	struct metalink_context ctx;

	ctx.sockfd = sockfd;
	ctx.priority = 999999;
	*ctx.hash = 0,
		*ctx.hash_type = 0,
		ctx.length = 0;
	strcpy(ctx.location, "-");

	mget_xml_parse_buffer(resp->body->data, _metalink4_parse, &ctx, 0);
}

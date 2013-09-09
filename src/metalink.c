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
 * Metalink parsing routines
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

#include "job.h"
#include "metalink.h"

struct metalink_context {
	JOB
		*job;
	int
		priority;
//		id; // counting piece number in metalink 3
	char
		hash[128],
		hash_type[16],
		location[8];
	long long
		length;
};

static void _metalink4_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	struct metalink_context *ctx = context;
	char value[len + 1];

	// info_printf("\n%02X %s %s '%s'\n", flags, dir, attr, value);
	if (!(flags & (XML_FLG_CONTENT | XML_FLG_ATTRIBUTE))) return; // ignore comments

	if (strncasecmp(dir, "/metalink/file", 14)) return;

	dir += 14;

	memcpy(value, val, len);
	value[len] = 0;

	if (attr) {
		if (*dir == 0) { // /metalink/file
			if (!strcasecmp(attr, "name")) {
				ctx->job->name = strdup(value);
			}
		} else if (!strcasecmp(dir, "/pieces")) {
			if (!strcasecmp(attr, "type")) {
				sscanf(value, "%15s", ctx->hash_type);
			} else if (!strcasecmp(attr, "length")) {
				ctx->length = atoll(value);
			}
		} else if (!strcasecmp(dir, "/hash")) {
			if (!strcasecmp(attr, "type")) {
				sscanf(value, "%15s", ctx->hash_type);
			}
		} else if (!strcasecmp(dir, "/url")) {
			if (!strcasecmp(attr, "location")) {
				sscanf(value, " %2[a-zA-Z]", ctx->location); // ISO 3166-1 alpha-2 two letter country code
			} else if (!strcasecmp(attr, "priority") || !strcasecmp(attr, "preference")) {
				sscanf(value, " %6d", &ctx->priority);
				if (ctx->priority < 1 || ctx->priority > 999999)
					ctx->priority = 999999;
			}
		}
	} else {
		if (!strcasecmp(dir, "/pieces/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (ctx->length && *ctx->hash_type && *ctx->hash) {
				// hash for a piece of the file
				PIECE piece, *piecep;

				if (!ctx->job->pieces)
					ctx->job->pieces = mget_vector_create(32, 32, NULL);

				piece.length = ctx->length;
				strcpy(piece.hash.type,ctx->hash_type);
				strcpy(piece.hash.hash_hex,ctx->hash);

				piecep = mget_vector_get(ctx->job->pieces, mget_vector_size(ctx->job->pieces) - 1);
				if (piecep)
					piece.position = piecep->position + piecep->length;
				mget_vector_add(ctx->job->pieces, &piece, sizeof(PIECE));
			}
			*ctx->hash = 0;
		} else if (!strcasecmp(dir, "/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (*ctx->hash_type && *ctx->hash) {
				// hashes for the complete file
				HASH hash;

				if (!ctx->job->hashes)
					ctx->job->hashes = mget_vector_create(4, 4, NULL);

				memset(&hash, 0, sizeof(HASH));
				strcpy(hash.type,ctx->hash_type);
				strcpy(hash.hash_hex,ctx->hash);
				mget_vector_add(ctx->job->hashes, &hash, sizeof(HASH));
			}
			*ctx->hash_type = *ctx->hash = 0;
		} else if (!strcasecmp(dir, "/size")) {
			ctx->job->size = atoll(value);
		} else if (!strcasecmp(dir, "/url")) {
			MIRROR mirror;

			if (!ctx->job->mirrors)
				ctx->job->mirrors = mget_vector_create(4, 4, NULL);

			memset(&mirror, 0, sizeof(MIRROR));
			strcpy(mirror.location, ctx->location);
			mirror.priority = ctx->priority;
			mirror.iri = mget_iri_parse(value, NULL);
			mget_vector_add(ctx->job->mirrors, &mirror, sizeof(MIRROR));

			*ctx->location = 0;
			ctx->priority = 999999;
		}
	}
}

void metalink4_parse(JOB *job, MGET_HTTP_RESPONSE *resp)
{
	struct metalink_context ctx = { .job = job, .priority = 999999, .location = "-" };

	mget_xml_parse_buffer(resp->body->data, _metalink4_parse, &ctx, 0);
}

static void _metalink3_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	struct metalink_context *ctx = context;
	char value[len + 1];

	// info_printf("\n%02X %s %s '%s'\n", flags, dir, attr, value);
	if (!(flags & (XML_FLG_CONTENT | XML_FLG_ATTRIBUTE))) return; // ignore comments

	if (strncasecmp(dir, "/metalink/files/file", 20)) return;

	dir += 20;

	memcpy(value, val, len);
	value[len] = 0;

	if (attr) {
		if (*dir == 0) { // /metalink/file
			if (!strcasecmp(attr, "name")) {
				ctx->job->name = strdup(value);
			}
			return;
		}

		if (!strcasecmp(dir, "/verification/pieces")) {
			if (!strcasecmp(attr, "type")) {
				sscanf(value, "%15s", ctx->hash_type);
			} else if (!strcasecmp(attr, "length")) {
				ctx->length = atoll(value);
			}
//		} else if (!strcasecmp(dir, "/verification/pieces/hash")) {
//			if (!strcasecmp(attr, "type")) {
//				ctx->id = atoi(value);
//			}
		} else if (!strcasecmp(dir, "/verification/hash")) {
			if (!strcasecmp(attr, "type")) {
				sscanf(value, "%15s", ctx->hash_type);
			}
		} else if (!strcasecmp(dir, "/resources/url")) {
			if (!strcasecmp(attr, "location")) {
				sscanf(value, " %2[a-zA-Z]", ctx->location); // ISO 3166-1 alpha-2 two letter country code
//			} else if (!strcasecmp(attr, "type")) {
//				sscanf(value, " %2[a-zA-Z]", ctx->type); // type of URL, e.g. HTTP, FTP, ...
			} else if (!strcasecmp(attr, "preference")) {
				sscanf(value, " %6d", &ctx->priority);
				if (ctx->priority < 1 || ctx->priority > 999999)
					ctx->priority = 999999;
			}
		}
	} else {
		if (!strcasecmp(dir, "/verification/pieces/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (ctx->length && *ctx->hash_type && *ctx->hash) {
				// hash for a piece of the file
				PIECE piece, *piecep;

				if (!ctx->job->pieces)
					ctx->job->pieces = mget_vector_create(32, 32, NULL);

				piece.length = ctx->length;
				strcpy(piece.hash.type,ctx->hash_type);
				strcpy(piece.hash.hash_hex,ctx->hash);

				piecep = mget_vector_get(ctx->job->pieces, mget_vector_size(ctx->job->pieces) - 1);
				if (piecep)
					piece.position = piecep->position + piecep->length;
				mget_vector_add(ctx->job->pieces, &piece, sizeof(PIECE));

			}
			*ctx->hash = 0;
		} else if (!strcasecmp(dir, "/verification/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (*ctx->hash_type && *ctx->hash) {
				// hashes for the complete file
				HASH hash;

				if (!ctx->job->hashes)
					ctx->job->hashes = mget_vector_create(4, 4, NULL);

				memset(&hash, 0, sizeof(HASH));
				strcpy(hash.type,ctx->hash_type);
				strcpy(hash.hash_hex,ctx->hash);
				mget_vector_add(ctx->job->hashes, &hash, sizeof(HASH));
			}
			*ctx->hash_type = *ctx->hash = 0;
		} else if (!strcasecmp(dir, "/size")) {
			ctx->job->size = atoll(value);
		} else if (!strcasecmp(dir, "/resources/url")) {
			MIRROR mirror;

			if (!ctx->job->mirrors)
				ctx->job->mirrors = mget_vector_create(4, 4, NULL);

			memset(&mirror, 0, sizeof(MIRROR));
			strcpy(mirror.location, ctx->location);
			mirror.priority = ctx->priority;
			mirror.iri = mget_iri_parse(value, NULL);
			mget_vector_add(ctx->job->mirrors, &mirror, sizeof(MIRROR));

			*ctx->location = 0;
			ctx->priority = 999999;
		}
	}
}

void metalink3_parse(JOB *job, MGET_HTTP_RESPONSE *resp)
{
	struct metalink_context ctx = { .job = job, .priority = 999999, .location = "-" };

	mget_xml_parse_buffer(resp->body->data, _metalink3_parse, &ctx, 0);
}

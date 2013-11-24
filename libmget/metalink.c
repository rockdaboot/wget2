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
 * Metalink parsing routines
 *
 * Changelog
 * 10.07.2012  Tim Ruehsen  created (refactored from mget.c)
 *
 * Resources:
 * RFC 5854 - The Metalink Download Description Format
 * RFC 6249 Metalink/HTTP: Mirrors and Hashes
 * RFC 5988 Link HTTP Header update
 * RFC 3864 Link HTTP Header
 * RFC 3230 Digest HTTP Header
 *
 * Some examples to test:
 * http://go-oo.mirrorbrain.org/stable/linux-x86/3.2.1/ooobasis3.2-af-calc-3.2.1-9505.i586.rpm
 * http://go-oo.mirrorbrain.org/stable/linux-x86/3.2.1/ooobasis3.2-ar-help-3.2.1-9505.i586.rpm
 * http://download.services.openoffice.org/files/stable/
 * http://go-oo.mirrorbrain.org/evolution/stable/Evolution-2.24.0.exe
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include <libmget.h>

#include "mget.h"

typedef struct {
	MGET_METALINK
		*metalink;
	int
		priority;
//		id; // counting piece number in metalink 3
	char
		hash[128],
		hash_type[16],
		location[8];
	long long
		length;
} _metalink_context_t ;

static void _free_mirror(MGET_METALINK_MIRROR *mirror)
{
	mget_iri_free(&mirror->iri);
}

static void _metalink4_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	_metalink_context_t *ctx = context;
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
				ctx->metalink->name = strndup(val, len);
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
		MGET_METALINK *metalink = ctx->metalink;

		if (!strcasecmp(dir, "/pieces/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (ctx->length && *ctx->hash_type && *ctx->hash) {
				// hash for a piece of the file
				MGET_METALINK_PIECE piece, *piecep;

				if (!metalink->pieces)
					metalink->pieces = mget_vector_create(32, 32, NULL);

				piece.length = ctx->length;
				strcpy(piece.hash.type, ctx->hash_type);
				strcpy(piece.hash.hash_hex, ctx->hash);

				piecep = mget_vector_get(metalink->pieces, mget_vector_size(metalink->pieces) - 1);
				if (piecep)
					piece.position = piecep->position + piecep->length;
				mget_vector_add(metalink->pieces, &piece, sizeof(MGET_METALINK_PIECE));
			}
			*ctx->hash = 0;
		} else if (!strcasecmp(dir, "/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (*ctx->hash_type && *ctx->hash) {
				// hashes for the complete file
				MGET_METALINK_HASH hash;

				if (!metalink->hashes)
					metalink->hashes = mget_vector_create(4, 4, NULL);

				memset(&hash, 0, sizeof(MGET_METALINK_HASH));
				strcpy(hash.type,ctx->hash_type);
				strcpy(hash.hash_hex,ctx->hash);
				mget_vector_add(metalink->hashes, &hash, sizeof(MGET_METALINK_HASH));
			}
			*ctx->hash_type = *ctx->hash = 0;
		} else if (!strcasecmp(dir, "/size")) {
			metalink->size = atoll(value);
		} else if (!strcasecmp(dir, "/url")) {
			MGET_METALINK_MIRROR mirror;

			if (!metalink->mirrors) {
				metalink->mirrors = mget_vector_create(4, 4, NULL);
				mget_vector_set_destructor(metalink->mirrors, (void(*)(void *))_free_mirror);
			}

			memset(&mirror, 0, sizeof(MGET_METALINK_MIRROR));
			strcpy(mirror.location, ctx->location);
			mirror.priority = ctx->priority;
			mirror.iri = mget_iri_parse(value, NULL);
			mget_vector_add(metalink->mirrors, &mirror, sizeof(MGET_METALINK_MIRROR));

			*ctx->location = 0;
			ctx->priority = 999999;
		}
	}
}

MGET_METALINK *metalink4_parse(const char *xml)
{
	MGET_METALINK *metalink = xcalloc(1, sizeof(MGET_METALINK));
	_metalink_context_t ctx = { .metalink = metalink, .priority = 999999, .location = "-" };

	mget_xml_parse_buffer(xml, _metalink4_parse, &ctx, 0);
	return metalink;
}

static void _metalink3_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	_metalink_context_t *ctx = context;
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
				ctx->metalink->name = strndup(val, len);
			}
		} else if (!strcasecmp(dir, "/verification/pieces")) {
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
		MGET_METALINK *metalink = ctx->metalink;

		if (!strcasecmp(dir, "/verification/pieces/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (ctx->length && *ctx->hash_type && *ctx->hash) {
				// hash for a piece of the file
				MGET_METALINK_PIECE piece, *piecep;

				if (!metalink->pieces)
					metalink->pieces = mget_vector_create(32, 32, NULL);

				piece.length = ctx->length;
				strcpy(piece.hash.type, ctx->hash_type);
				strcpy(piece.hash.hash_hex, ctx->hash);

				piecep = mget_vector_get(metalink->pieces, mget_vector_size(metalink->pieces) - 1);
				if (piecep)
					piece.position = piecep->position + piecep->length;
				mget_vector_add(metalink->pieces, &piece, sizeof(MGET_METALINK_PIECE));

			}
			*ctx->hash = 0;
		} else if (!strcasecmp(dir, "/verification/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (*ctx->hash_type && *ctx->hash) {
				// hashes for the complete file
				MGET_METALINK_HASH hash;

				if (!metalink->hashes)
					metalink->hashes = mget_vector_create(4, 4, NULL);

				memset(&hash, 0, sizeof(MGET_METALINK_HASH));
				strcpy(hash.type,ctx->hash_type);
				strcpy(hash.hash_hex,ctx->hash);
				mget_vector_add(metalink->hashes, &hash, sizeof(MGET_METALINK_HASH));
			}
			*ctx->hash_type = *ctx->hash = 0;
		} else if (!strcasecmp(dir, "/size")) {
			metalink->size = atoll(value);
		} else if (!strcasecmp(dir, "/resources/url")) {
			MGET_METALINK_MIRROR mirror;

			if (!metalink->mirrors)
				metalink->mirrors = mget_vector_create(4, 4, NULL);

			memset(&mirror, 0, sizeof(MGET_METALINK_MIRROR));
			strcpy(mirror.location, ctx->location);
			mirror.priority = ctx->priority;
			mirror.iri = mget_iri_parse(value, NULL);
			mget_vector_add(metalink->mirrors, &mirror, sizeof(MGET_METALINK_MIRROR));

			*ctx->location = 0;
			ctx->priority = 999999;
		}
	}
}

MGET_METALINK *metalink3_parse(const char *xml)
{
	MGET_METALINK *metalink = xcalloc(1, sizeof(MGET_METALINK));
	_metalink_context_t ctx = { .metalink = metalink, .priority = 999999, .location = "-" };

	mget_xml_parse_buffer(xml, _metalink3_parse, &ctx, 0);
	return metalink;
}

void mget_metalink_free(MGET_METALINK **metalink)
{
	if (metalink && *metalink) {
		xfree((*metalink)->name);
		mget_vector_free(&(*metalink)->mirrors);
		mget_vector_free(&(*metalink)->hashes);
		mget_vector_free(&(*metalink)->pieces);
		xfree(*metalink);
	}
}

static int G_GNUC_MGET_PURE _compare_mirror(MGET_METALINK_MIRROR **m1, MGET_METALINK_MIRROR **m2)
{
	return (*m1)->priority - (*m2)->priority;
}

void mget_metalink_sort_mirrors(MGET_METALINK *metalink)
{
	if (metalink) {
		mget_vector_setcmpfunc(metalink->mirrors, (int(*)(const void *, const void *))_compare_mirror);
		mget_vector_sort(metalink->mirrors);
	}
}

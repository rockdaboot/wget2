/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * Metalink parsing routines
 *
 * Changelog
 * 10.07.2012  Tim Ruehsen  created (refactored from wget.c)
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <c-ctype.h>

#include <wget.h>
#include "private.h"

typedef struct {
	wget_metalink_t
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

static void _free_mirror(wget_metalink_mirror_t *mirror)
{
	wget_iri_free(&mirror->iri);
}

static void _add_piece(_metalink_context_t *ctx, const char *value)
{
	wget_metalink_t *metalink = ctx->metalink;

	sscanf(value, "%127s", ctx->hash);

	if (ctx->length && *ctx->hash_type && *ctx->hash) {
		// hash for a piece of the file
		wget_metalink_piece_t piece, *piecep;

		if (!metalink->pieces)
			metalink->pieces = wget_vector_create(32, 32, NULL);

		piece.length = ctx->length;
		wget_strscpy(piece.hash.type, ctx->hash_type, sizeof(piece.hash.type));
		wget_strscpy(piece.hash.hash_hex, ctx->hash, sizeof(piece.hash.hash_hex));

		piecep = wget_vector_get(metalink->pieces, wget_vector_size(metalink->pieces) - 1);
		if (piecep && piecep->length > 0) {
			if (piecep->position <= LONG_MAX - piecep->length)
				piece.position = piecep->position + piecep->length;
			else
				piece.position = 0; // integer overflow
		} else
			piece.position = 0;
		wget_vector_add(metalink->pieces, &piece, sizeof(wget_metalink_piece_t));
	}

	*ctx->hash = 0;
}

static void _add_file_hash(_metalink_context_t *ctx, const char *value)
{
	wget_metalink_t *metalink = ctx->metalink;

	sscanf(value, "%127s", ctx->hash);

	if (*ctx->hash_type && *ctx->hash) {
		// hashes for the complete file
		wget_metalink_hash_t hash;

		memset(&hash, 0, sizeof(wget_metalink_hash_t));
		wget_strscpy(hash.type, ctx->hash_type, sizeof(hash.type));
		wget_strscpy(hash.hash_hex, ctx->hash, sizeof(hash.hash_hex));

		if (!metalink->hashes)
			metalink->hashes = wget_vector_create(4, 4, NULL);
		wget_vector_add(metalink->hashes, &hash, sizeof(wget_metalink_hash_t));
	}

	*ctx->hash_type = *ctx->hash = 0;
}

static void _add_mirror(_metalink_context_t *ctx, const char *value)
{
	while (c_isspace(*value))
		value++;

	if (wget_strncasecmp_ascii(value, "http:", 5) && wget_strncasecmp_ascii(value, "https:", 6))
		return;

	wget_metalink_t *metalink = ctx->metalink;
	wget_metalink_mirror_t mirror;

	memset(&mirror, 0, sizeof(wget_metalink_mirror_t));
	wget_strscpy(mirror.location, ctx->location, sizeof(mirror.location));
	mirror.priority = ctx->priority;
	mirror.iri = wget_iri_parse(value, NULL);

	if (!mirror.iri)
		return;

	if (!metalink->mirrors) {
		metalink->mirrors = wget_vector_create(4, 4, NULL);
		wget_vector_set_destructor(metalink->mirrors, (wget_vector_destructor_t)_free_mirror);
	}
	wget_vector_add(metalink->mirrors, &mirror, sizeof(wget_metalink_mirror_t));

	*ctx->location = 0;
	ctx->priority = 999999;
}

static void _metalink_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos G_GNUC_WGET_UNUSED)
{
	_metalink_context_t *ctx = context;
	char value[len + 1];

	// info_printf("\n%02X %s %s '%s'\n", flags, dir, attr, value);
	if (!(flags & (XML_FLG_CONTENT | XML_FLG_ATTRIBUTE))) return; // ignore comments

	if (wget_strncasecmp_ascii(dir, "/metalink/file", 14)) return;

	dir += 14;

	if (val)
			memcpy(value, val, len);
	value[len] = 0;

	if (!wget_strncasecmp_ascii(dir, "s/file", 6)) {
		// metalink 3 XML format
		dir += 6;

		if (attr) {
			if (*dir == 0) { // /metalink/file
				if (!ctx->metalink->name && !wget_strcasecmp_ascii(attr, "name")) {
					ctx->metalink->name = wget_strdup(value);
				}
			} else if (!wget_strcasecmp_ascii(dir, "/verification/pieces")) {
				if (!wget_strcasecmp_ascii(attr, "type")) {
					sscanf(value, "%15s", ctx->hash_type);
				} else if (!wget_strcasecmp_ascii(attr, "length")) {
					ctx->length = atoll(value);
				}
//			} else if (!wget_strcasecmp_ascii(dir, "/verification/pieces/hash")) {
//				if (!wget_strcasecmp_ascii(attr, "type")) {
//					ctx->id = atoi(value);
//				}
			} else if (!wget_strcasecmp_ascii(dir, "/verification/hash")) {
				if (!wget_strcasecmp_ascii(attr, "type")) {
					sscanf(value, "%15s", ctx->hash_type);
				}
			} else if (!wget_strcasecmp_ascii(dir, "/resources/url")) {
				if (!wget_strcasecmp_ascii(attr, "location")) {
					sscanf(value, " %2[a-zA-Z]", ctx->location); // ISO 3166-1 alpha-2 two letter country code
//				} else if (!wget_strcasecmp_ascii(attr, "protocol")) {
//					sscanf(value, " %7[a-zA-Z]", ctx->protocol); // type of URL, e.g. HTTP, HTTPS, FTP, ...
//				} else if (!wget_strcasecmp_ascii(attr, "type")) {
//					sscanf(value, " %2[a-zA-Z]", ctx->type); // type of URL, e.g. HTTP, FTP, ...
				} else if (!wget_strcasecmp_ascii(attr, "preference")) {
					sscanf(value, " %6d", &ctx->priority);
					if (ctx->priority < 1 || ctx->priority > 999999)
						ctx->priority = 999999;
				}
			}
		} else {
			if (!wget_strcasecmp_ascii(dir, "/verification/pieces/hash")) {
				_add_piece(ctx, value);
			} else if (!wget_strcasecmp_ascii(dir, "/verification/hash")) {
				_add_file_hash(ctx, value);
			} else if (!wget_strcasecmp_ascii(dir, "/size")) {
				ctx->metalink->size = atoll(value);
			} else if (!wget_strcasecmp_ascii(dir, "/resources/url")) {
				_add_mirror(ctx, value);
			}
		}
	} else {
		// metalink 4 XML format
		if (attr) {
			if (*dir == 0) { // /metalink/file
				if (!ctx->metalink->name && !wget_strcasecmp_ascii(attr, "name")) {
					ctx->metalink->name = wget_strdup(value);
				}
			} else if (!wget_strcasecmp_ascii(dir, "/pieces")) {
				if (!wget_strcasecmp_ascii(attr, "type")) {
					sscanf(value, "%15s", ctx->hash_type);
				} else if (!wget_strcasecmp_ascii(attr, "length")) {
					ctx->length = atoll(value);
				}
			} else if (!wget_strcasecmp_ascii(dir, "/hash")) {
				if (!wget_strcasecmp_ascii(attr, "type")) {
					sscanf(value, "%15s", ctx->hash_type);
				}
			} else if (!wget_strcasecmp_ascii(dir, "/url")) {
				if (!wget_strcasecmp_ascii(attr, "location")) {
					sscanf(value, " %2[a-zA-Z]", ctx->location); // ISO 3166-1 alpha-2 two letter country code
				} else if (!wget_strcasecmp_ascii(attr, "priority") || !wget_strcasecmp_ascii(attr, "preference")) {
					sscanf(value, " %6d", &ctx->priority);
					if (ctx->priority < 1 || ctx->priority > 999999)
						ctx->priority = 999999;
				}
			}
		} else {
			if (!wget_strcasecmp_ascii(dir, "/pieces/hash")) {
				_add_piece(ctx, value);
			} else if (!wget_strcasecmp_ascii(dir, "/hash")) {
				_add_file_hash(ctx, value);
			} else if (!wget_strcasecmp_ascii(dir, "/size")) {
				ctx->metalink->size = atoll(value);
			} else if (!wget_strcasecmp_ascii(dir, "/url")) {
				_add_mirror(ctx, value);
			}
		}
	}
}

wget_metalink_t *wget_metalink_parse(const char *xml)
{
	wget_metalink_t *metalink = xcalloc(1, sizeof(wget_metalink_t));
	_metalink_context_t ctx = { .metalink = metalink, .priority = 999999, .location = "-" };

	wget_xml_parse_buffer(xml, _metalink_parse, &ctx, 0);
	return metalink;
}

void wget_metalink_free(wget_metalink_t **metalink)
{
	if (metalink && *metalink) {
		xfree((*metalink)->name);
		wget_vector_free(&(*metalink)->mirrors);
		wget_vector_free(&(*metalink)->hashes);
		wget_vector_free(&(*metalink)->pieces);
		xfree(*metalink);
	}
}

static int G_GNUC_WGET_PURE _compare_mirror(wget_metalink_mirror_t **m1, wget_metalink_mirror_t **m2)
{
	return (*m1)->priority - (*m2)->priority;
}

void wget_metalink_sort_mirrors(wget_metalink_t *metalink)
{
	if (metalink) {
		wget_vector_setcmpfunc(metalink->mirrors, (wget_vector_compare_t)_compare_mirror);
		wget_vector_sort(metalink->mirrors);
	}
}

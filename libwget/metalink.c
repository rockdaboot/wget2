/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include <libwget.h>
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

static void _metalink4_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos G_GNUC_WGET_UNUSED)
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
			if (!wget_strcasecmp_ascii(attr, "name")) {
				ctx->metalink->name = strndup(val, len);
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
		wget_metalink_t *metalink = ctx->metalink;

		if (!wget_strcasecmp_ascii(dir, "/pieces/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (ctx->length && *ctx->hash_type && *ctx->hash) {
				// hash for a piece of the file
				wget_metalink_piece_t piece, *piecep;

				if (!metalink->pieces)
					metalink->pieces = wget_vector_create(32, 32, NULL);

				piece.length = ctx->length;
				strlcpy(piece.hash.type, ctx->hash_type, sizeof(piece.hash.type));
				strlcpy(piece.hash.hash_hex, ctx->hash, sizeof(piece.hash.hash_hex));

				piecep = wget_vector_get(metalink->pieces, wget_vector_size(metalink->pieces) - 1);
				if (piecep)
					piece.position = piecep->position + piecep->length;
				wget_vector_add(metalink->pieces, &piece, sizeof(wget_metalink_piece_t));
			}
			*ctx->hash = 0;
		} else if (!wget_strcasecmp_ascii(dir, "/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (*ctx->hash_type && *ctx->hash) {
				// hashes for the complete file
				wget_metalink_hash_t hash;

				memset(&hash, 0, sizeof(wget_metalink_hash_t));
				strlcpy(hash.type, ctx->hash_type, sizeof(hash.type));
				strlcpy(hash.hash_hex, ctx->hash, sizeof(hash.hash_hex));

				if (!metalink->hashes)
					metalink->hashes = wget_vector_create(4, 4, NULL);
				wget_vector_add(metalink->hashes, &hash, sizeof(wget_metalink_hash_t));
			}
			*ctx->hash_type = *ctx->hash = 0;
		} else if (!wget_strcasecmp_ascii(dir, "/size")) {
			metalink->size = atoll(value);
		} else if (!wget_strcasecmp_ascii(dir, "/url")) {
			wget_metalink_mirror_t mirror;

			memset(&mirror, 0, sizeof(wget_metalink_mirror_t));
			strlcpy(mirror.location, ctx->location, sizeof(mirror.location));
			mirror.priority = ctx->priority;
			mirror.iri = wget_iri_parse(value, NULL);

			if (!metalink->mirrors) {
				metalink->mirrors = wget_vector_create(4, 4, NULL);
				wget_vector_set_destructor(metalink->mirrors, (void(*)(void *))_free_mirror);
			}
			wget_vector_add(metalink->mirrors, &mirror, sizeof(wget_metalink_mirror_t));

			*ctx->location = 0;
			ctx->priority = 999999;
		}
	}
}

wget_metalink_t *metalink4_parse(const char *xml)
{
	wget_metalink_t *metalink = xcalloc(1, sizeof(wget_metalink_t));
	_metalink_context_t ctx = { .metalink = metalink, .priority = 999999, .location = "-" };

	wget_xml_parse_buffer(xml, _metalink4_parse, &ctx, 0);
	return metalink;
}

static void _metalink3_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos G_GNUC_WGET_UNUSED)
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
			if (!wget_strcasecmp_ascii(attr, "name")) {
				ctx->metalink->name = strndup(val, len);
			}
		} else if (!wget_strcasecmp_ascii(dir, "/verification/pieces")) {
			if (!wget_strcasecmp_ascii(attr, "type")) {
				sscanf(value, "%15s", ctx->hash_type);
			} else if (!wget_strcasecmp_ascii(attr, "length")) {
				ctx->length = atoll(value);
			}
//		} else if (!wget_strcasecmp_ascii(dir, "/verification/pieces/hash")) {
//			if (!wget_strcasecmp_ascii(attr, "type")) {
//				ctx->id = atoi(value);
//			}
		} else if (!wget_strcasecmp_ascii(dir, "/verification/hash")) {
			if (!wget_strcasecmp_ascii(attr, "type")) {
				sscanf(value, "%15s", ctx->hash_type);
			}
		} else if (!wget_strcasecmp_ascii(dir, "/resources/url")) {
			if (!wget_strcasecmp_ascii(attr, "location")) {
				sscanf(value, " %2[a-zA-Z]", ctx->location); // ISO 3166-1 alpha-2 two letter country code
//			} else if (!strcasecmp(attr, "type")) {
//				sscanf(value, " %2[a-zA-Z]", ctx->type); // type of URL, e.g. HTTP, FTP, ...
			} else if (!wget_strcasecmp_ascii(attr, "preference")) {
				sscanf(value, " %6d", &ctx->priority);
				if (ctx->priority < 1 || ctx->priority > 999999)
					ctx->priority = 999999;
			}
		}
	} else {
		wget_metalink_t *metalink = ctx->metalink;

		if (!wget_strcasecmp_ascii(dir, "/verification/pieces/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (ctx->length && *ctx->hash_type && *ctx->hash) {
				// hash for a piece of the file
				wget_metalink_piece_t piece, *piecep;

				if (!metalink->pieces)
					metalink->pieces = wget_vector_create(32, 32, NULL);

				piece.length = ctx->length;
				strlcpy(piece.hash.type, ctx->hash_type, sizeof(piece.hash.type));
				strlcpy(piece.hash.hash_hex, ctx->hash, sizeof(piece.hash.hash_hex));

				piecep = wget_vector_get(metalink->pieces, wget_vector_size(metalink->pieces) - 1);
				if (piecep)
					piece.position = piecep->position + piecep->length;
				wget_vector_add(metalink->pieces, &piece, sizeof(wget_metalink_piece_t));

			}
			*ctx->hash = 0;
		} else if (!wget_strcasecmp_ascii(dir, "/verification/hash")) {
			sscanf(value, "%127s", ctx->hash);
			if (*ctx->hash_type && *ctx->hash) {
				// hashes for the complete file
				wget_metalink_hash_t hash;

				memset(&hash, 0, sizeof(wget_metalink_hash_t));
				strlcpy(hash.type, ctx->hash_type, sizeof(hash.type));
				strlcpy(hash.hash_hex, ctx->hash, sizeof(hash.hash_hex));

				if (!metalink->hashes)
					metalink->hashes = wget_vector_create(4, 4, NULL);
				wget_vector_add(metalink->hashes, &hash, sizeof(wget_metalink_hash_t));
			}
			*ctx->hash_type = *ctx->hash = 0;
		} else if (!wget_strcasecmp_ascii(dir, "/size")) {
			metalink->size = atoll(value);
		} else if (!wget_strcasecmp_ascii(dir, "/resources/url")) {
			wget_metalink_mirror_t mirror;

			memset(&mirror, 0, sizeof(wget_metalink_mirror_t));
			strlcpy(mirror.location, ctx->location, sizeof(mirror.location));
			mirror.priority = ctx->priority;
			mirror.iri = wget_iri_parse(value, NULL);

			if (!metalink->mirrors)
				metalink->mirrors = wget_vector_create(4, 4, NULL);
			wget_vector_add(metalink->mirrors, &mirror, sizeof(wget_metalink_mirror_t));

			*ctx->location = 0;
			ctx->priority = 999999;
		}
	}
}

wget_metalink_t *metalink3_parse(const char *xml)
{
	wget_metalink_t *metalink = xcalloc(1, sizeof(wget_metalink_t));
	_metalink_context_t ctx = { .metalink = metalink, .priority = 999999, .location = "-" };

	wget_xml_parse_buffer(xml, _metalink3_parse, &ctx, 0);
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
		wget_vector_setcmpfunc(metalink->mirrors, (int(*)(const void *, const void *))_compare_mirror);
		wget_vector_sort(metalink->mirrors);
	}
}

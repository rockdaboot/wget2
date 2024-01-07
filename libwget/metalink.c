/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
#include <limits.h>

#include <wget.h>
#include "private.h"

typedef struct {
	wget_metalink
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
} metalink_context ;

static void mirror_free(void *mirror)
{
	wget_metalink_mirror *m = mirror;

	if (m) {
		wget_iri_free((wget_iri **) &m->iri);
		xfree(m);
	}
}

static void add_piece(metalink_context *ctx, const char *value)
{
	wget_metalink *metalink = ctx->metalink;

	sscanf(value, "%127s", ctx->hash);

	if (ctx->length && *ctx->hash_type && *ctx->hash) {
		// hash for a piece of the file
		wget_metalink_piece piece, *piecep;

		if (!metalink->pieces)
			metalink->pieces = wget_vector_create(32, NULL);

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
		wget_vector_add_memdup(metalink->pieces, &piece, sizeof(wget_metalink_piece));
	}

	*ctx->hash = 0;
}

static void add_file_hash(metalink_context *ctx, const char *value)
{
	wget_metalink *metalink = ctx->metalink;

	sscanf(value, "%127s", ctx->hash);

	if (*ctx->hash_type && *ctx->hash) {
		// hashes for the complete file
		wget_metalink_hash hash = { 0 };

		wget_strscpy(hash.type, ctx->hash_type, sizeof(hash.type));
		wget_strscpy(hash.hash_hex, ctx->hash, sizeof(hash.hash_hex));

		if (!metalink->hashes)
			metalink->hashes = wget_vector_create(4, NULL);
		wget_vector_add_memdup(metalink->hashes, &hash, sizeof(wget_metalink_hash));
	}

	*ctx->hash_type = *ctx->hash = 0;
}

static void add_mirror(metalink_context *ctx, const char *value)
{
	wget_iri *iri = wget_iri_parse(value, NULL);

	if (!iri)
		return;

	if (!wget_iri_supported(iri)) {
		error_printf(_("Mirror scheme not supported: '%s'\n"), value);
		wget_iri_free(&iri);
		return;
	}

/*	if (iri->scheme == WGET_IRI_SCHEME_HTTP)
		test_modify_hsts(iri);

	if (config.https_only && iri->scheme != WGET_IRI_SCHEME_HTTPS) {
		info_printf(_("Mirror '%s' dropped (https-only requested)\n"), value);
		wget_iri_free(&iri);
		return;
	}

	if (iri->scheme == WGET_IRI_SCHEME_HTTP && config.https_enforce) {
		wget_iri_set_scheme(iri, WGET_IRI_SCHEME_HTTPS);
	}
*/

	wget_metalink *metalink = ctx->metalink;
	wget_metalink_mirror *mirror = wget_calloc(1, sizeof(wget_metalink_mirror));

	if (mirror) {
		wget_strscpy(mirror->location, ctx->location, sizeof(mirror->location));
		mirror->priority = ctx->priority;
		mirror->iri = iri;

		if (!metalink->mirrors) {
			metalink->mirrors = wget_vector_create(4, NULL);
			wget_vector_set_destructor(metalink->mirrors, mirror_free);
		}
		wget_vector_add(metalink->mirrors, mirror);
	}

	*ctx->location = 0;
	ctx->priority = 999999;
}

static void metalink_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos WGET_GCC_UNUSED)
{
	metalink_context *ctx = context;
	char valuebuf[1024];
	const char *value;

	// info_printf("\n%02X %s %s '%s'\n", flags, dir, attr, value);
	if (!(flags & (XML_FLG_CONTENT | XML_FLG_ATTRIBUTE)))
		return; // ignore comments

	if (wget_strncasecmp_ascii(dir, "/metalink/file", 14))
		return;

	dir += 14;

	if (!(value = wget_strmemcpy_a(valuebuf, sizeof(valuebuf), val ? val : "", len)))
		return;

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
				add_piece(ctx, value);
			} else if (!wget_strcasecmp_ascii(dir, "/verification/hash")) {
				add_file_hash(ctx, value);
			} else if (!wget_strcasecmp_ascii(dir, "/size")) {
				ctx->metalink->size = atoll(value);
			} else if (!wget_strcasecmp_ascii(dir, "/resources/url")) {
				add_mirror(ctx, value);
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
				add_piece(ctx, value);
			} else if (!wget_strcasecmp_ascii(dir, "/hash")) {
				add_file_hash(ctx, value);
			} else if (!wget_strcasecmp_ascii(dir, "/size")) {
				ctx->metalink->size = atoll(value);
			} else if (!wget_strcasecmp_ascii(dir, "/url")) {
				add_mirror(ctx, value);
			}
		}
	}

	if (value != valuebuf)
		xfree(value);
}

wget_metalink *wget_metalink_parse(const char *xml)
{
	if (!xml)
		return NULL;

	wget_metalink *metalink = wget_calloc(1, sizeof(wget_metalink));
	metalink_context ctx = { .metalink = metalink, .priority = 999999, .location = "-" };

	if (wget_xml_parse_buffer(xml, metalink_parse, &ctx, 0) != WGET_E_SUCCESS) {
		error_printf(_("Error in parsing XML"));
		wget_metalink_free(&metalink);
	}

	return metalink;
}

void wget_metalink_free(wget_metalink **metalink)
{
	if (metalink && *metalink) {
		xfree((*metalink)->name);
		wget_vector_free(&(*metalink)->mirrors);
		wget_vector_free(&(*metalink)->hashes);
		wget_vector_free(&(*metalink)->pieces);
		xfree(*metalink);
	}
}

WGET_GCC_PURE
static int compare_mirror(wget_metalink_mirror **m1, wget_metalink_mirror **m2)
{
	return (*m1)->priority - (*m2)->priority;
}

void wget_metalink_sort_mirrors(wget_metalink *metalink)
{
	if (metalink) {
		wget_vector_setcmpfunc(metalink->mirrors, (wget_vector_compare_fn *) compare_mirror);
		wget_vector_sort(metalink->mirrors);
	}
}

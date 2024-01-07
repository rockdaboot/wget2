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
 * stringmap routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include <wget.h>
#include "private.h"

static wget_hashmap_hash_fn hash_string, hash_string_nocase;

// Paul Larson's hash function from Microsoft Research
#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
WGET_GCC_PURE
static unsigned int hash_string(const void *key)
{
	const char *k = key;
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*k)
		hash = hash * 101 + (unsigned char)*k++;

	return hash;
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
WGET_GCC_PURE
static unsigned int hash_string_nocase(const void *key)
{
	const char *k = key;
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*k)
		hash = hash * 101 + (unsigned char)tolower(*k++);

	return hash;
}

/**
 * \file
 * \brief Stringmap functions
 * \defgroup libwget-stringmap Stringmap functions
 * @{
 *
 * Stringmaps are key/value stores that perform at O(1) for insertion, searching and removing.
 * The key is a C string.
 *
 * These functions are a wrapper around the Hashmap API.
 */

/**
 * \param[in] max Initial number of pre-allocated entries
 * \return New stringmap instance
 *
 * Create a new stringmap instance with initial size \p max.
 * It should be free'd after use with wget_stringmap_free().
 *
 * The hash function is an efficient string hash algorithm originally researched by Paul Larson.
 *
 * The compare function is strcmp(). The key strings are compared case-sensitive.
 */
wget_stringmap *wget_stringmap_create(int max)
{
	return wget_hashmap_create(max, hash_string, (wget_hashmap_compare_fn *) wget_strcmp);
}

/**
 * \param[in] max Initial number of pre-allocated entries
 * \return New stringmap instance
 *
 * Create a new stringmap instance with initial size \p max.
 * It should be free'd after use with wget_stringmap_free().
 *
 * The hash function is an efficient string hash algorithm originally researched by Paul Larson, using
 * lowercase'd keys.
 *
 * The compare function is strcasecmp() (case-insensitive).
 */
wget_stringmap *wget_stringmap_create_nocase(int max)
{
	return wget_hashmap_create(max, hash_string_nocase, (wget_hashmap_compare_fn *) wget_strcasecmp);
}

/**@}*/

/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Functions for bitmap
 * \defgroup libwget-bitmap Bitmap management functions
 *
 * @{
 *
 * Bitmap (bit array) implementation.
 *
 * This is useful when you need a bitmap with more than 64 bits. Up to 64 bits you can
 * use the C99 uint64_t as a standard C bitfield.
 *
 * As a usage example, Wget2 uses bitmaps for options with lists of HTTP status codes, which have values
 * of 100-699.
 *
 */

#define bitmap_type   uint64_t
#define bitmap_bits   (sizeof(bitmap_type) * 8)
#define bitmap_shift  6 // ln(bitmap_bits)/ln(2)

#define map(n) (((wget_bitmap *)b)->map[(n) >> bitmap_shift])
#define bit(n) (((bitmap_type) 1) << ((n) & (bitmap_bits - 1)))

struct wget_bitmap_st {
	bitmap_type
		bits;
	bitmap_type
		map[];
};

/**
 * \param b Bitmap to act on
 * \param n Number of the bit to set (0-...)
 *
 * Set the bit \p n in the bitmap \p b.
 */

void wget_bitmap_set(wget_bitmap *b, unsigned n)
{
	if (b && n < ((wget_bitmap *) b)->bits)
		map(n) |= bit(n);
}

/**
 * \param b Bitmap to act on
 * \param n Number of the bit to clear (0-...)
 *
 * Clear the bit \p n in the bitmap \p b.
 */
void wget_bitmap_clear(wget_bitmap *b, unsigned n)
{
	if (b && n < ((wget_bitmap *) b)->bits)
		map(n) &= ~bit(n);
}

/**
 * \param[in] b Bitmap to read from
 * \param[in] n Number of the bit of interest (0-...)
 * \return
 * 0 if bit \p n is cleared or if \p n is out of range
 * 1 if bit \p is set
 *
 * Returns whether the bit \p n is set or not.
 */
bool wget_bitmap_get(const wget_bitmap *b, unsigned n)
{
	if (b && n < ((wget_bitmap *) b)->bits)
		return (map(n) & bit(n)) != 0;

	return 0;
}

/**
 * \param[out] b Pointer to the allocated bitmap
 * \param[in] bits Number of bits
 * \return A \ref wget_error value
 *
 * Allocates a bitmap with a capacity of \p bits.
 * It must be freed by wget_bitmap_free() after usage.
 */
int wget_bitmap_init(wget_bitmap **b, unsigned bits)
{
	if (!b)
		return WGET_E_INVALID;

	wget_bitmap *_b =
		wget_calloc((bits + sizeof(bitmap_type) - 1) / sizeof(bitmap_type) + 1, sizeof(bitmap_type));

	if (!_b)
		return WGET_E_MEMORY;

	_b->bits = bits;
	*b = _b;

	return WGET_E_SUCCESS;
}

/**
 * \param[in] b Pointer to bitmap to free
 *
 * Frees and clears the bitmap pointed to by \p b.
 */
void wget_bitmap_free(wget_bitmap **b)
{
	if (b)
		xfree(*b);
}

/** @} */

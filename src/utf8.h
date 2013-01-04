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
 * Header file for utf-8 conversion routines
 *
 * Changelog
 * 10.12.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_UTF8_H
#define _MGET_UTF8_H

#include <stddef.h>

char
	*str_to_utf8(const char *src, const char *encoding) G_GNUC_MGET_MALLOC;

#endif /* _MGET_UTF8_H */

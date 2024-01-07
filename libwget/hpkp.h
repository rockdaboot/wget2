/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file for HPKP code
 */

#ifndef LIBWGET_HPKP_H
#define LIBWGET_HPKP_H

#include <wget.h>

struct wget_hpkp_st {
	const char *
		host;
	int64_t
		expires;
	int64_t
		created;
	int64_t
		maxage;
	wget_vector *
		pins;
	bool
		include_subdomains : 1;
};

typedef struct {
	const char *
		pin_b64; /* base64 encoded <pin> */
	const void *
		pin; /* binary hash */
	const char *
		hash_type; /* type of <pin>, e.g. 'sha-256' */
	size_t
		pinsize; /* size of <pin> */
} wget_hpkp_pin;


#endif /* LIBWGET_HPKP_H */

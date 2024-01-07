/*
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
 * HTTP Public Key Pinning (HPKP)
 */

#include <config.h>

#include <wget.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <sys/stat.h>
#include <limits.h>
#include "private.h"
#include "hpkp.h"

/**
 * \file
 * \brief HTTP Public Key Pinning (RFC 7469) routines
 * \defgroup libwget-hpkp HTTP Public Key Pinning (RFC 7469) routines
 * @{
 *
 * This is an implementation of RFC 7469.
 */

/*
 * Compare function for SPKI hashes. Returns 0 if they're equal.
 */
WGET_GCC_NONNULL_ALL
static int compare_pin(wget_hpkp_pin *p1, wget_hpkp_pin *p2)
{
	int n;

	if ((n = strcmp(p1->hash_type, p2->hash_type)))
		return n;

	if (p1->pinsize < p2->pinsize)
		return -1;

	if (p1->pinsize > p2->pinsize)
		return 1;

	return memcmp(p1->pin, p2->pin, p1->pinsize);
}

static void hpkp_pin_free(void *pin)
{
	wget_hpkp_pin *p = pin;

	if (p) {
		xfree(p->hash_type);
		xfree(p->pin);
		xfree(p->pin_b64);
		xfree(p);
	}
}

/**
 * \param[in] hpkp An HPKP database entry
 * \param[in] pin_type The type of hash supplied, e.g. "sha256"
 * \param[in] pin_b64 The public key hash in base64 format
 *
 * Adds a public key hash to HPKP database entry.
 */
void wget_hpkp_pin_add(wget_hpkp *hpkp, const char *pin_type, const char *pin_b64)
{
	wget_hpkp_pin *pin = wget_calloc(1, sizeof(wget_hpkp_pin));
	if (!pin)
		return;

	size_t len_b64 = strlen(pin_b64);

	pin->hash_type = wget_strdup(pin_type);
	pin->pin_b64 = wget_strdup(pin_b64);
	pin->pin = (unsigned char *) wget_base64_decode_alloc(pin_b64, len_b64, &pin->pinsize);

	if (!hpkp->pins) {
		hpkp->pins = wget_vector_create(5, (wget_vector_compare_fn *) compare_pin);
		wget_vector_set_destructor(hpkp->pins, hpkp_pin_free);
	}

	wget_vector_add(hpkp->pins, pin);
}

/**
 * \param[in] hpkp An HPKP database entry
 *
 * Free hpkp_t instance created by wget_hpkp_new()
 * It can be used as destructor function in vectors and hashmaps.
 * If `hpkp` is NULL this function does nothing.
 */
void wget_hpkp_free(wget_hpkp *hpkp)
{
	if (hpkp) {
		xfree(hpkp->host);
		wget_vector_free(&hpkp->pins);
		xfree(hpkp);
	}
}

/*
 * TODO HPKP: wget_hpkp_new() should get an IRI rather than a string, and check by itself
 * whether it is HTTPS, not an IP literal, etc.
 *
 * This is also applicable to HSTS.
 */
/**
 * \return A newly allocated and initialized HPKP structure
 *
 * Creates a new HPKP structure initialized with the given values.
 */
wget_hpkp *wget_hpkp_new(void)
{
	wget_hpkp *hpkp = wget_calloc(1, sizeof(wget_hpkp));

	if (hpkp)
		hpkp->created = time(NULL);

	return hpkp;
}

/**
 * \param[in] hpkp An HPKP database entry
 * \param[in] host Hostname of the web server
 *
 * Sets the hostname of the web server into given HPKP database entry.
 */
void wget_hpkp_set_host(wget_hpkp *hpkp, const char *host)
{
	xfree(hpkp->host);
	hpkp->host = wget_strdup(host);
}

/**
 * \param[in] hpkp An HPKP database entry
 * \param[in] maxage Maximum time the entry is valid (in seconds)
 *
 * Sets the maximum time the HPKP entry is valid.
 * Corresponds to `max-age` directive in `Public-Key-Pins` HTTP response header.
 */
void wget_hpkp_set_maxage(wget_hpkp *hpkp, int64_t maxage)
{
	int64_t now;

	// avoid integer overflow here
	if (maxage <= 0 || maxage >= INT64_MAX / 2 || (now = time(NULL)) < 0 || now >= INT64_MAX / 2) {
		hpkp->maxage = 0;
		hpkp->expires = 0;
	} else {
		hpkp->maxage = maxage;
		hpkp->expires = now + maxage;
	}
}

/**
 * \param[in] hpkp An HPKP database entry
 * \param[in] include_subdomains Nonzero if this entry is also valid for all subdomains, zero otherwise.
 *
 * Sets whether the entry is also valid for all subdomains.
 * Corresponds to the optional `includeSubDomains` directive in `Public-Key-Pins` HTTP response header.
 */
void wget_hpkp_set_include_subdomains(wget_hpkp *hpkp, bool include_subdomains)
{
	hpkp->include_subdomains = include_subdomains;
}

/**
 * \param[in] hpkp An HPKP database entry
 * \return The number of public key hashes added.
 *
 * Gets the number of public key hashes added to the given HPKP database entry.
 */
int wget_hpkp_get_n_pins(wget_hpkp *hpkp)
{
	return wget_vector_size(hpkp->pins);
}

/**
 * \param[in] hpkp An HPKP database entry
 * \param[out] pin_types An array of pointers where hash types will be stored.
 * \param[out] pins_b64 An array of pointers where the public keys in base64 format will be stored
 *
 * Gets all the public key hashes added to the given HPKP database entry.
 *
 * The size of the arrays used must be at least one returned by \ref wget_hpkp_get_n_pins "wget_hpkp_get_n_pins()".
 */
void wget_hpkp_get_pins_b64(wget_hpkp *hpkp, const char **pin_types, const char **pins_b64)
{
	int i, n_pins;

	n_pins = wget_vector_size(hpkp->pins);

	for (i = 0; i < n_pins; i++) {
		wget_hpkp_pin *pin = (wget_hpkp_pin *) wget_vector_get(hpkp->pins, i);
		if (!pin)
			continue;
		pin_types[i] = pin->hash_type;
		pins_b64[i] = pin->pin_b64;
	}
}

/**
 * \param[in] hpkp An HPKP database entry
 * \param[out] pin_types An array of pointers where hash types will be stored.
 * \param[out] sizes An array of sizes where pin sizes will be stored.
 * \param[out] pins An array of pointers where the public keys in binary format will be stored
 *
 * Gets all the public key hashes added to the given HPKP database entry.
 *
 * The size of the arrays used must be at least one returned by \ref wget_hpkp_get_n_pins "wget_hpkp_get_n_pins()".
 */
void wget_hpkp_get_pins(wget_hpkp *hpkp, const char **pin_types, size_t *sizes, const void **pins)
{
	int i, n_pins;

	n_pins = wget_vector_size(hpkp->pins);

	for (i = 0; i < n_pins; i++) {
		wget_hpkp_pin *pin = (wget_hpkp_pin *) wget_vector_get(hpkp->pins, i);
		if (!pin)
			continue;
		pin_types[i] = pin->hash_type;
		sizes[i] = pin->pinsize;
		pins[i] = pin->pin;
	}
}

/**
 * \param[in] hpkp An HPKP database entry
 * \return The hostname this entry is valid for
 *
 * Gets the hostname this entry is valid for, as set by \ref wget_hpkp_set_host "wget_hpkp_set_host()"
 */
const char * wget_hpkp_get_host(wget_hpkp *hpkp)
{
	return hpkp->host;
}

/**
 * \param[in] hpkp An HPKP database entry
 * \return The maximum time (in seconds) the entry is valid
 *
 * Gets the maximum time this entry is valid for, as set by \ref wget_hpkp_set_maxage "wget_hpkp_set_maxage()"
 */
int64_t wget_hpkp_get_maxage(wget_hpkp *hpkp)
{
	return hpkp->maxage;
}

/**
 * \param[in] hpkp An HPKP database entry
 * \return `true` if the HPKP entry is also valid for all subdomains, `false` otherwise
 *
 * Gets whether the HPKP database entry is also valid for the subdomains.
 */
bool wget_hpkp_get_include_subdomains(wget_hpkp *hpkp)
{
	return hpkp->include_subdomains;
}

/**@}*/

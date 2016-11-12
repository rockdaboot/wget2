/*
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * HTTP Public Key Pinning
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <wget.h>
#include <string.h>
#include <stddef.h>
#include "private.h"

struct _wget_hpkp_db_st {
	wget_hashmap_t *
		entries;
	wget_thread_mutex_t
		mutex;
};

struct _wget_hpkp_st {
	const char *
		host;
	time_t
		created;
	time_t
		max_age;
	char
		include_subdomains;
	wget_vector_t *
		pins;
};

/*
 * TODO HPKP: include target port as well.
 */
static unsigned int G_GNUC_WGET_PURE _hash_hpkp(const void *data)
{
	unsigned int hash = 1;
	const unsigned char *p;

	for (p = (unsigned char *) data; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

/*
 * TODO HPKP: include target port as well.
 */
static int _cmp_hpkp(const void *h1, const void *h2)
{
	return !strcmp(h1, h2);
}

/*
 * Callback for comparing two SPKI hashes. Should return 0 if they're equal.
 * Currently HPKP only supports SHA-256 hashing.
 * This gives us 256 bits == 32 bytes output.
 * So we test byte-for-byte 32 times.
 */
static int _cmp_pins(const void *P1, const void *P2)
{
	const uint8_t *p1 = P1, *p2 = P2;
	uint8_t all_equal = 1;

	/* We're dealing with public values anyway, so we can speed up the comparison */
	for (int i = 0; i < 32 && all_equal; i++) {
		if (p1[i] != p2[i])
			all_equal = 0;
	}

	return (int) !all_equal;
}

/*
 * This is a callback function to destroy an hpkp entry.
 * It will be invoked by the hash table.
 */
static void wget_hpkp_free(wget_hpkp_t *hpkp)
{
	if (hpkp) {
		/* No need to free hpkp->host. It's already been freed by the hash table. */
		wget_vector_clear(hpkp->pins);
		xfree(hpkp);
	}
}

wget_hpkp_t *wget_hpkp_new(const char *host, time_t max_age, int include_subdomains)
{
	wget_hpkp_t *hpkp = xmalloc(sizeof(wget_hpkp_t));

	memset(hpkp, 0, sizeof(wget_hpkp_t));
	hpkp->host = wget_strdup(host);
	hpkp->created = time(NULL);
	hpkp->max_age = max_age;
	hpkp->include_subdomains = include_subdomains;

	/*
	 * Currently HPKP only supports SHA-256 hashing.
	 * Should it support more hash functions in the future,
	 * we should modify the _cmp_pins function somehow.
	 *
	 * Also, we don't need a destructor. Default behavior is to xfree() the values,
	 * which is OK, since wget_hpkp_add_public_key_base64() allocates new copies.
	 */
	hpkp->pins = wget_vector_create(3, 3, _cmp_pins);

	return hpkp;
}

wget_hpkp_db_t *wget_hpkp_db_init()
{
	wget_hpkp_db_t *hpkp_db = xmalloc(sizeof(wget_hpkp_db_t));

	hpkp_db->entries = wget_hashmap_create(16, -2,
			(unsigned int (*) (const void *)) _hash_hpkp,
			_cmp_hpkp);
	/*
	 * Keys are hosts: the hpkp->host field, which is strdup-ed in wget_hpkp_new(),
	 * so we have to free it. But the default key destructor is free(),
	 * so we don't have to set it ourselves.
	 *
	 * Values are wget_hpkp_t structures, so we have to destroy them manually.
	 * This is done in the wget_hpkp_free() function.
	 */
	wget_hashmap_set_value_destructor(hpkp_db->entries,
			(void (*) (void *)) wget_hpkp_free);

	wget_thread_mutex_init(&hpkp_db->mutex);

	return hpkp_db;
}


void wget_hpkp_db_deinit(wget_hpkp_db_t **hpkp_db)
{
	if (hpkp_db && *hpkp_db) {
		wget_thread_mutex_lock(&(*hpkp_db)->mutex);
		wget_hashmap_free(&(*hpkp_db)->entries);
		wget_thread_mutex_unlock(&(*hpkp_db)->mutex);

		xfree(*hpkp_db);
	}
}

void wget_hpkp_add_public_key_base64(wget_hpkp_t *hpkp, const char *b64_pubkey)
{
	if (!hpkp || !b64_pubkey)
		return;

	//size_t pubkey_len = wget_base64_get_decoded_length(strlen(b64_pubkey));
	char *pubkey = wget_base64_decode_alloc(b64_pubkey, strlen(b64_pubkey));

	if (!wget_vector_contains(hpkp->pins, pubkey))
		wget_vector_add_noalloc(hpkp->pins, pubkey);
	else
		xfree(pubkey);
}

/*
 * TODO HPKP: think on return values (retval should be checked by caller)
 */
int wget_hpkp_db_add(wget_hpkp_db_t *hpkp_db, wget_hpkp_t *hpkp_new)
{
	time_t curtime = time(NULL);

	if (!hpkp_db || !hpkp_new || !hpkp_new->host)
		return -1;

	/* Check whether entry is expired already */
	if ((hpkp_new->created + hpkp_new->max_age) < curtime)
		return -1;

	wget_hpkp_t *hpkp = wget_hashmap_get(hpkp_db->entries, hpkp_new->host);

	if (hpkp == NULL && hpkp_new->max_age != 0) {
		/* This entry is not a Known PH, so we add it */
		wget_hashmap_put_noalloc(hpkp_db->entries, hpkp_new->host, hpkp_new);
	} else if (hpkp && hpkp_new->max_age != 0 &&
			hpkp->created < hpkp_new->created &&
			(hpkp->include_subdomains != hpkp_new->include_subdomains ||
			hpkp->max_age != hpkp_new->max_age)) {
		hpkp->include_subdomains = hpkp_new->include_subdomains;
		hpkp->max_age = hpkp_new->max_age;
	} else if (hpkp && hpkp_new->max_age == 0) {
		wget_hashmap_remove(hpkp_db->entries, hpkp_new->host);
	}

	return 0;
}

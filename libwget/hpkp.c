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

/*
 * TODO HPKP: implement this
 */
static wget_hpkp_t *__wget_hpkp_new(const char *host, time_t created, time_t max_age, int include_subdomains)
{
	wget_hpkp_t *hpkp = xcalloc(1, sizeof(wget_hpkp_t));

	hpkp->host = wget_strdup(host);
	hpkp->created = created;
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

/*
 * TODO HPKP: wget_hpkp_new() should get an IRI rather than a string, and check by itself
 * whether it is HTTPS, not an IP literal, etc.
 *
 * This is also applicable to HSTS.
 */
wget_hpkp_t *wget_hpkp_new(const char *host, time_t max_age, int include_subdomains)
{
	wget_hpkp_t *hpkp;
	time_t created = time(NULL);

	if (created == -1)
		created = 0;
	hpkp = __wget_hpkp_new(host, created, max_age, include_subdomains);

	return hpkp;
}

wget_hpkp_db_t *wget_hpkp_db_init()
{
	wget_hpkp_db_t *hpkp_db = xcalloc(1, sizeof(wget_hpkp_db_t));

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

void wget_hpkp_db_free(wget_hpkp_db_t *hpkp_db)
{
	if (hpkp_db) {
		wget_thread_mutex_lock(&hpkp_db->mutex);
		wget_hashmap_free(&hpkp_db->entries);
		wget_thread_mutex_unlock(&hpkp_db->mutex);
	}
}

void wget_hpkp_db_deinit(wget_hpkp_db_t **hpkp_db)
{
	if (hpkp_db && *hpkp_db) {
		wget_hpkp_db_free(*hpkp_db);
		xfree(*hpkp_db);
	}
}

void wget_hpkp_add_public_key_base64(wget_hpkp_t *hpkp, const char *b64_pubkey)
{
	if (!hpkp || !hpkp->pins || !b64_pubkey)
		return;

	//size_t pubkey_len = wget_base64_get_decoded_length(strlen(b64_pubkey));
	char *pubkey = wget_base64_decode_alloc(b64_pubkey, strlen(b64_pubkey));

	if (!wget_vector_contains(hpkp->pins, pubkey)) {
		wget_vector_add_noalloc(hpkp->pins, pubkey);
		wget_debug_printf("Added public key pin '%s'\n", b64_pubkey);
	} else {
		xfree(pubkey);
		wget_debug_printf("Public key pin '%s' already in list. Skipping.\n", b64_pubkey);
	}
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

static int __vector_browse_cb(void *ctx, void *elem)
{
	FILE *fp = ctx;
	const char *hash = elem, *b64_hash;

	if (!hash)
		return -1;

	b64_hash = wget_base64_encode_alloc(hash, 32);
	/* As said before, only SHA-256 is supported for now */
	fprintf(fp, "sha-256\t%s\n", b64_hash);
	xfree(b64_hash);

	return 0;
}

static int __hashtable_browse_cb(void *ctx, const void *key, void *value)
{
	int retval;
	FILE *fp = ctx;
	const char *url = key;
	const wget_hpkp_t *hpkp = value;

	if (!hpkp->pins)
		return -1;

	unsigned int num_pins = wget_vector_size(hpkp->pins);
	if (num_pins > 0) {
		fprintf(fp, "%s\t%lu\t%lu\t%u\t%u\n",
				url,
				hpkp->created, hpkp->max_age,
				hpkp->include_subdomains,
				num_pins);

		retval = wget_vector_browse(hpkp->pins, __vector_browse_cb, fp);
	} else {
		retval = -1;
	}

	return retval;
}

/*
 * TODO HPKP: think on return values
 */
int wget_hpkp_db_save(const char *filename, wget_hpkp_db_t *hpkp_db)
{
	FILE *fp;
	int retval;

	if (!filename || !*filename || !hpkp_db || !hpkp_db->entries)
		return -1;

	fp = fopen(filename, "w");
	if (!fp)
		return -1;

	fprintf(fp, "# HTTP Public Key Pinning database (RFC 7469)\n");
	fprintf(fp, "# Generated by wget2\n");
	fprintf(fp, "# MODIFY AT YOUR OWN RISK\n");

	wget_thread_mutex_lock(&hpkp_db->mutex);
	retval = wget_hashmap_browse(hpkp_db->entries, __hashtable_browse_cb, fp);
	wget_thread_mutex_unlock(&hpkp_db->mutex);

	fclose(fp);
	return retval;
}

enum hpkp_parse_state {
	PARSING_HOST,
	PARSING_PIN,
	ERROR_CONTINUE,
	ERROR
};

static enum hpkp_parse_state __wget_hpkp_parse_host_line(const char *line, ssize_t len,
		char **host_out,
		time_t *created, time_t *max_age, char *include_subdomains,
		unsigned int *num_pins)
{
	wget_iri_t *iri = NULL;
	char host[len + 1];
	enum hpkp_parse_state new_state = ERROR;

	sscanf(line, "%s\t%lu\t%lu\t%u\t%u",
			host,
			created, max_age, (unsigned int *) include_subdomains,
			num_pins);
	/* We try to parse the host here to verify if it's valid */
	/* TODO should we store the encoding in the database file as well? */
	/* TODO maybe we should add a new field 'encoding' to wget_iri_t */
	iri = wget_iri_parse(host, "utf-8");
	if (!iri)
		goto end;
	if (iri->is_ip_address) {
		new_state = ERROR_CONTINUE;
		wget_error_printf("Host '%s' is a literal IP address. Skipping.\n", iri->host);
		goto end;
	}
	*host_out = wget_strdup(host);

//	sscanf(line, "%lu\t%lu\t%c\t%u",
//			created, max_age, include_subdomains,
//			num_pins);

	if (*num_pins > 0) {
		new_state = PARSING_PIN;
		wget_info_printf("Found %u public key pins\n", *num_pins);
	} else {
		wget_error_printf("No pins found\n");
	}

end:
	if (iri)
		wget_iri_free(&iri);
	return new_state;
}

static enum hpkp_parse_state __wget_hpkp_parse_pin_line(const char *line, ssize_t len, wget_hpkp_t *hpkp, unsigned int *num_pins)
{
	enum hpkp_parse_state new_state = ERROR;
	char sha256_magic[len + 1];
	/* Same as before. Only SHA-256 is supported for now. */
	char *b64_pin = NULL;

	if (sscanf(line, "%s\t%ms", sha256_magic, &b64_pin) != 2)
		goto end;
	if (wget_strcmp(sha256_magic, "sha-256")) {
		wget_error_printf("Only 'sha-256' hashes are supported.\n");
		goto end;
	}
//	if (strcmp(hash_alg, "sha-256"))
//		goto end;

//	sscanf(line, "%ms", &b64_pin);
	wget_hpkp_add_public_key_base64(hpkp, b64_pin);

	if (--*num_pins > 0)
		new_state = PARSING_PIN;
	else
		new_state = PARSING_HOST;

end:
	xfree(b64_pin);
	return new_state;
}

int wget_hpkp_db_load(const char *filename, wget_hpkp_db_t *hpkp_db)
{
	int retval = 0;
	FILE *fp;
	wget_hpkp_t *hpkp = NULL;
	char *buf, should_continue = 1;
	size_t bufsize = 0;
	ssize_t buflen;
	char *host = NULL;
	time_t created, max_age;
	char include_subdomains;
	unsigned int num_pins = 0;
	enum hpkp_parse_state state = PARSING_HOST;

	if (!filename || !*filename || !hpkp_db)
		return -1;

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	do {
		buflen = wget_getline(&buf, &bufsize, fp);
		if (buflen >= 0 && buf[0] != '#') {
			if (state == PARSING_HOST) {
				state = __wget_hpkp_parse_host_line(buf, buflen,
						&host,
						&created, &max_age, &include_subdomains,
						&num_pins);
				if (state == ERROR) {
					wget_error_printf("Error parsing host in line '%s'\n", buf);
					goto fail;
				}

				if (state != ERROR_CONTINUE) {
					hpkp = __wget_hpkp_new(host, created, max_age, include_subdomains);

					wget_thread_mutex_lock(&hpkp_db->mutex);
					wget_hashmap_put_noalloc(hpkp_db->entries, host, hpkp);
					wget_thread_mutex_unlock(&hpkp_db->mutex);
				}

				xfree(host);
			} else if (state == PARSING_PIN) {
				state = __wget_hpkp_parse_pin_line(buf, buflen,
						hpkp,
						&num_pins);
				if (state == ERROR) {
					wget_error_printf("Error parsing pin in line '%s'\n", buf);
					goto fail;
				}
			}

			if (state == ERROR)
				should_continue = 0;
		} else if (buflen < 0) {
			if (state == PARSING_HOST)
				wget_hpkp_free(hpkp);
			should_continue = 0;
		}
	} while (should_continue);
	xfree(buf);
	goto end;

fail:
	if (hpkp)
		wget_hpkp_free(hpkp);
	wget_hpkp_db_free(hpkp_db);
	xfree(host);
	retval = -1;
end:
	fclose(fp);
	return retval;
}

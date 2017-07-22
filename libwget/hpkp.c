/*
 * Copyright(c) 2015-2017 Free Software Foundation, Inc.
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
 * HTTP Public Key Pinning
 *
 */

#include <config.h>

#include <wget.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>
#include <sys/stat.h>
#include <limits.h>
#include "private.h"

struct _wget_hpkp_db_st {
	wget_hashmap_t *
		entries;
	wget_thread_mutex_t
		mutex;
	time_t
		load_time;
};

struct _wget_hpkp_st {
	const char *
		host;
	time_t
		expires;
	time_t
		created;
	time_t
		maxage;
	char
		include_subdomains;
	wget_vector_t *
		pins;
};

struct _wget_hpkp_pin_st {
	const char *
		pin_b64; /* base64 encoded <pin> */
	const void *
		pin; /* binary hash */
	const char *
		hash_type; /* type of <pin>, e.g. 'sha-256' */
	size_t
		pinsize; /* size of <pin> */
};
typedef struct _wget_hpkp_pin_st wget_hpkp_pin_t;

/**
 * \file
 * \brief HTTP Public Key Pinning (RFC 7469) routines
 * \defgroup libwget-hpkp HTTP Public Key Pinning (RFC 7469) routines
 * @{
 *
 * This is an implementation of RFC 7469.
 */

static unsigned int G_GNUC_WGET_PURE _hash_hpkp(const wget_hpkp_t *hpkp)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)hpkp->host; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static int G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PURE _compare_hpkp(const wget_hpkp_t *h1, const wget_hpkp_t *h2)
{
	return strcmp(h1->host, h2->host);
}

/*
 * Compare function for SPKI hashes. Returns 0 if they're equal.
 */
static int G_GNUC_WGET_NONNULL_ALL _compare_pin(wget_hpkp_pin_t *p1, wget_hpkp_pin_t *p2)
{
	int n;

	if (!(n = strcmp(p1->hash_type, p2->hash_type)))
		return memcmp(p1->pin, p2->pin, p1->pinsize);

	return n;
}

static void _hpkp_pin_free(wget_hpkp_pin_t *pin)
{
	if (pin) {
		xfree(pin->hash_type);
		xfree(pin->pin);
		xfree(pin->pin_b64);
	}
}

void wget_hpkp_pin_add(wget_hpkp_t *hpkp, const char *pin_type, const char *pin_b64)
{
	wget_hpkp_pin_t *pin = xcalloc(1, sizeof(wget_hpkp_pin_t));
	size_t len_b64 = strlen(pin_b64);

	pin->hash_type = wget_strdup(pin_type);
	pin->pin_b64 = wget_strdup(pin_b64);
	pin->pin = (unsigned char *)wget_base64_decode_alloc(pin_b64, len_b64);
	pin->pinsize = wget_base64_get_decoded_length(len_b64);

	if (!hpkp->pins) {
		hpkp->pins = wget_vector_create(5, -2, (wget_vector_compare_t)_compare_pin);
		wget_vector_set_destructor(hpkp->pins, (wget_vector_destructor_t)_hpkp_pin_free);
	}

	wget_vector_add_noalloc(hpkp->pins, pin);
}

/*
 * Free hpkp_t instance created by wget_hpkp_new()
 * It can be used as destructor function in vectors and hashmaps.
 */
void wget_hpkp_free(wget_hpkp_t *hpkp)
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
wget_hpkp_t *wget_hpkp_new(void)
{
	wget_hpkp_t *hpkp = xcalloc(1, sizeof(wget_hpkp_t));

	hpkp->created = time(NULL);

	return hpkp;
}

void wget_hpkp_set_host(wget_hpkp_t *hpkp, const char *host)
{
	xfree(hpkp->host);
	hpkp->host = wget_strdup(host);
}

void wget_hpkp_set_maxage(wget_hpkp_t *hpkp, time_t maxage)
{
	hpkp->maxage = maxage;
	hpkp->expires = maxage ? time(NULL) + maxage : 0;
}

void wget_hpkp_set_include_subdomains(wget_hpkp_t *hpkp, int include_subdomains)
{
	hpkp->include_subdomains = !!include_subdomains;
}

/**
 * \return Handle (pointer) to an HPKP database
 *
 * Initializes a new HPKP database.
 */
wget_hpkp_db_t *wget_hpkp_db_init(wget_hpkp_db_t *hpkp_db)
{
	if (!hpkp_db)
		hpkp_db = xcalloc(1, sizeof(wget_hpkp_db_t));
	else
		memset(hpkp_db, 0, sizeof(*hpkp_db));

	hpkp_db->entries = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_hpkp, (wget_hashmap_compare_t)_compare_hpkp);
	wget_hashmap_set_key_destructor(hpkp_db->entries, (wget_hashmap_key_destructor_t)wget_hpkp_free);

	/*
	 * Keys and values for the hashmap are 'hpkp' entries, so value == key.
	 * The hash function hashes hostname.
	 * The compare function compares hostname.
	 *
	 * Since the value == key, we just need the value destructor for freeing hashmap entries.
	 */

	wget_thread_mutex_init(&hpkp_db->mutex);

	return hpkp_db;
}

void wget_hpkp_db_deinit(wget_hpkp_db_t *hpkp_db)
{
	if (hpkp_db) {
		wget_thread_mutex_lock(&hpkp_db->mutex);
		wget_hashmap_free(&hpkp_db->entries);
		wget_thread_mutex_unlock(&hpkp_db->mutex);
	}
}

/**
 * \param[in] hpkp_db Pointer to the pointer of an HPKP database, provided by wget_hpkp_db_init()
 *
 * Closes and frees the HPKP database. A double pointer is required because this function will
 * set the handle (pointer) to the HPKP database to NULL to prevent potential use-after-free conditions.
 */
void wget_hpkp_db_free(wget_hpkp_db_t **hpkp_db)
{
	if (hpkp_db) {
		wget_hpkp_db_deinit(*hpkp_db);
		xfree(*hpkp_db);
	}
}

/*
static int _wget_hpkp_contains_pin(wget_hpkp_t *hpkp, wget_hpkp_pin_t *pin)
{
	return !wget_vector_contains(hpkp->pins, pin);
}

static int _wget_hpkp_compare_pins(wget_hpkp_t *hpkp1, wget_hpkp_t *hpkp2)
{
	return wget_vector_browse(hpkp1->pins, (wget_vector_browse_t)_wget_hpkp_contains_pin, hpkp2);
}
*/

int wget_hpkp_db_check_pubkey(wget_hpkp_db_t *hpkp_db, const char *host, const void *pubkey, size_t pubkeysize)
{
	wget_hpkp_t key;
	wget_hpkp_t *hpkp = NULL;
	char digest[wget_hash_get_len(WGET_DIGTYPE_SHA256)];
	int subdomain = 0;

	for (const char *domain = host; *domain && !hpkp; domain = strchrnul(domain, '.')) {
		while (*domain == '.')
			domain++;

		key.host = domain;
		hpkp = wget_hashmap_get(hpkp_db->entries, &key);

		if (!hpkp)
			subdomain = 1;
	}

	if (!hpkp)
		return 0; // OK, host is not in database

	if (subdomain && !hpkp->include_subdomains)
		return 0; // OK, found a matching super domain which isn't responsible for <host>

	if (wget_hash_fast(WGET_DIGTYPE_SHA256, pubkey, pubkeysize, digest))
		return -1;

	wget_hpkp_pin_t pinkey = { .pin = digest, .pinsize = sizeof(digest), .hash_type = "sha256" };

	if (wget_vector_find(hpkp->pins, &pinkey) != -1)
		return 1; // OK, pinned pubkey found

	return -2;
}

/* We 'consume' _hpkp and thus set *_hpkp to NULL, so that the calling function
 * can't access it any more */
void wget_hpkp_db_add(wget_hpkp_db_t *hpkp_db, wget_hpkp_t **_hpkp)
{
	if (!_hpkp || !*_hpkp)
		return;

	wget_hpkp_t *hpkp = *_hpkp;

	wget_thread_mutex_lock(&hpkp_db->mutex);

	if (hpkp->maxage == 0 || wget_vector_size(hpkp->pins) == 0) {
		if (wget_hashmap_remove(hpkp_db->entries, hpkp))
			debug_printf("removed HPKP %s\n", hpkp->host);
		wget_hpkp_free(hpkp);
	} else {
		wget_hpkp_t *old = wget_hashmap_get(hpkp_db->entries, hpkp);

		if (old) {
			old->created = hpkp->created;
			old->maxage = hpkp->maxage;
			old->expires = hpkp->expires;
			old->include_subdomains = hpkp->include_subdomains;
			wget_vector_free(&old->pins);
			old->pins = hpkp->pins;
			hpkp->pins = NULL;
			debug_printf("update HPKP %s (maxage=%lld, includeSubDomains=%d)\n", old->host, (long long)old->maxage, old->include_subdomains);
			wget_hpkp_free(hpkp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'hpkp'
			/* debug_printf("add HPKP %s (maxage=%lld, includeSubDomains=%d)\n", hpkp->host, (long long)hpkp->maxage, hpkp->include_subdomains); */
			wget_hashmap_put_noalloc(hpkp_db->entries, hpkp, hpkp);
			// no need to free anything here
		}
	}

	*_hpkp = NULL;

	wget_thread_mutex_unlock(&hpkp_db->mutex);
}

/**
 * \param[in] hpkp_db Handle to an HPKP database, obtained with wget_hpkp_db_init()
 * \param[in] fname Path to a file
 * \return WGET_HPKP_OK on success, or a negative number on error
 *
 * Reads the file specified by `filename` and loads its contents into the HPKP database
 * provided by `hpkp_db`.
 *
 * If this function cannot correctly parse the whole file, `WGET_HPKP_ERROR` is returned.
 * Since the format of the file might change without notice, hand-crafted files are discouraged.
 * To create an HPKP database file that is guaranteed to be correctly parsed by this function,
 * wget_hpkp_db_save() should be used.
 *
 * The entries in the file are subject to sanity checks as if they were added to the HPKP database
 * via wget_hpkp_db_add(). In particular, if an entry is expired due to `creation_time + max_age > cur_time`
 * it will not be added to the database, and a subsequent call to wget_hpkp_db_save() with the same `hpkp_db` handle
 * and file name will overwrite the file without all the expired entries. Thus, if all the entries in the file are
 * expired, the database will be empty and a subsequent call to wget_hpkp_db_save() with the same parameters will
 * cause the file to be deleted.
 *
 * If the file cannot be opened for writing `WGET_HPKP_ERROR_FILE_OPEN` is returned,
 * or `WGET_HPKP_ERROR` in any other case.
 */
static int _hpkp_db_load(wget_hpkp_db_t *hpkp_db, FILE *fp)
{
	time_t created, max_age;
	long long int _created, _max_age;
	int include_subdomains;

	wget_hpkp_t *hpkp = NULL;
	struct stat st;
	char *buf = NULL, *linep;
	size_t bufsize = 0;
	ssize_t buflen;
	char hash_type[32], host[256], pin_b64[256];
	time_t now = time(NULL);

	// if the database file hasn't changed since the last read
	// there's no need to reload

	if (fstat(fileno(fp), &st) == 0) {
		if (st.st_mtime != hpkp_db->load_time)
			hpkp_db->load_time = st.st_mtime;
		else
			return 0;
	}

	while ((buflen = wget_getline(&buf, &bufsize, fp)) >= 0) {
		linep = buf;

		while (isspace(*linep)) linep++; // ignore leading whitespace
		if (!*linep) continue; // skip empty lines

		if (*linep == '#')
			continue; // skip comments

		// strip off \r\n
		while (buflen > 0 && (buf[buflen] == '\n' || buf[buflen] == '\r'))
			buf[--buflen] = 0;

		if (*linep != '*') {
			wget_hpkp_db_add(hpkp_db, &hpkp);

			if (sscanf(linep, "%255s %d %lld %lld", host, &include_subdomains, &_created, &_max_age) == 4) {
				created = (time_t)_created;
				max_age = (time_t) _max_age;
				if (max_age && (created + max_age) >= now) {
					hpkp = wget_hpkp_new();
					hpkp->host = wget_strdup(host);
					hpkp->maxage = max_age;
					hpkp->created = created;
					hpkp->expires = created + max_age;
					hpkp->include_subdomains = !!include_subdomains;
				} else
					debug_printf("HPKP: entry '%s' is expired\n", host);
			} else {
				error_printf("HPKP: could not parse host line '%s'\n", buf);
			}
		} else if (hpkp) {
			if (sscanf(linep, "*%31s %255s", hash_type, pin_b64) == 2) {
				wget_hpkp_pin_add(hpkp, hash_type, pin_b64);
			} else {
				error_printf("HPKP: could not parse pin line '%s'\n", buf);
			}
		} else {
			debug_printf("HPKP: skipping PIN entry: '%s'\n", buf);
		}
	}

	wget_hpkp_db_add(hpkp_db, &hpkp);

	xfree(buf);

	if (ferror(fp)) {
		hpkp_db->load_time = 0; // reload on next call to this function
		return -1;
	}

	return 0;
}

int wget_hpkp_db_load(wget_hpkp_db_t *hpkp_db, const char *fname)
{
	if (!hpkp_db || !fname || !*fname)
		return 0;

	if (wget_update_file(fname, (wget_update_load_t)_hpkp_db_load, NULL, hpkp_db)) {
		error_printf(_("Failed to read HPKP data\n"));
		return -1;
	} else {
		debug_printf("Fetched HPKP data from '%s'\n", fname);
		return 0;
	}
}

static int _hpkp_save_pin(FILE *fp, wget_hpkp_pin_t *pin)
{
	fprintf(fp, "*%s %s\n", pin->hash_type, pin->pin_b64);

	if (ferror(fp))
		return -1;

	return 0;
}

static int G_GNUC_WGET_NONNULL_ALL _hpkp_save(FILE *fp, const wget_hpkp_t *hpkp)
{
	if (wget_vector_size(hpkp->pins) == 0)
		debug_printf("HPKP: drop '%s', no PIN entries\n", hpkp->host);
	else if (hpkp->expires < time(NULL))
		debug_printf("HPKP: drop '%s', expired\n", hpkp->host);
	else {
		fprintf(fp, "%s %d %lld %lld\n", hpkp->host, hpkp->include_subdomains, (long long)hpkp->created, (long long)hpkp->maxage);

		if (ferror(fp))
			return -1;

		return wget_vector_browse(hpkp->pins, (wget_vector_browse_t)_hpkp_save_pin, fp);
	}

	return 0;
}

static int _hpkp_db_save(wget_hpkp_db_t *hpkp_db, FILE *fp)
{
	wget_hashmap_t *entries = hpkp_db->entries;

	if (wget_hashmap_size(entries) > 0) {
		fputs("# HPKP 1.0 file\n", fp);
		fputs("#Generated by Wget2 " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		fputs("#<hostname> <incl. subdomains> <created> <max-age>\n\n", fp);

		if (ferror(fp))
			return -1;

		return wget_hashmap_browse(entries, (wget_hashmap_browse_t)_hpkp_save, fp);
	}

	return 0;
}

/**
 * \param[in] hpkp_db Handle to an HPKP database, obtained with wget_hpkp_db_init()
 * \param[in] fname Path to a file
 * \return The number of SPKIs written to the file, or a negative number on error.
 *
 * Saves the current HPKP database to the specified file.
 *
 * The information will be stored in a human-readable format for inspection,
 * but it is discouraged to rely on it for external processing. In particular,
 * no application other than wget2 should modify the contents of the file
 * as the format might change between releases without notice.
 *
 * This function returns the number of SPKIs written to the file, which is effectively
 * equal to the number of SPKIs in the database when this function was called, and thus,
 * might be zero. If the file specified by `filename` exists, all its contents
 * will be overwritten with the current contents of the database. Otherwise, if the file exists
 * but there are no SPKIs in the database, the file will be deleted to avoid leaving an empty file.
 *
 * If the file cannot be opened for writing `WGET_HPKP_ERROR_FILE_OPEN` is returned, and
 * `WGET_HPKP_ERROR` in any other case.
 */
int wget_hpkp_db_save(wget_hpkp_db_t *hpkp_db, const char *fname)
{
	int size;

	if (!hpkp_db || !fname || !*fname)
		return -1;

	if (wget_update_file(fname, (wget_update_load_t)_hpkp_db_load, (wget_update_load_t)_hpkp_db_save, hpkp_db)) {
		error_printf(_("Failed to write HPKP file '%s'\n"), fname);
		return -1;
	}

	if ((size = wget_hashmap_size(hpkp_db->entries)))
		debug_printf("Saved %d HPKP entr%s into '%s'\n", size, size != 1 ? "ies" : "y", fname);
	else
		debug_printf("No HPKP entries to save. Table is empty.\n");

	return 0;
}

/**@}*/

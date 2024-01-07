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
 * HTTP Public Key Pinning database
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
 * \ingroup libwget-hpkp
 *
 * HTTP Public Key Pinning (RFC 7469) database implementation
 *
 * @{
 */

struct wget_hpkp_db_st {
	char *
		fname;
	wget_hashmap *
		entries;
	wget_thread_mutex
		mutex;
	int64_t
		load_time;
};

/// Pointer to the function table
static const wget_hpkp_db_vtable
	*plugin_vtable;

void wget_hpkp_set_plugin(const wget_hpkp_db_vtable *vtable)
{
	plugin_vtable = vtable;
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
WGET_GCC_PURE
static unsigned int hash_hpkp(const wget_hpkp *hpkp)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)hpkp->host; *p; p++)
		hash = hash * 101 + *p; // possible integer overflow, suppression above

	return hash;
}

WGET_GCC_NONNULL_ALL WGET_GCC_PURE
static int compare_hpkp(const wget_hpkp *h1, const wget_hpkp *h2)
{
	return strcmp(h1->host, h2->host);
}

/**
 * \param[in] hpkp_db Pointer to the pointer of an HPKP database, provided by wget_hpkp_db_init()
 *
 * Frees all resources allocated for the HPKP database, except for the structure.
 *
 * Works only for databases created by wget_hpkp_db_init().
 * The parameter \p hpkp_db can then be passed to \ref wget_hpkp_db_init "wget_hpkp_db_init()".
 *
 * If \p hpkp_db is NULL then this function does nothing.
 */
void wget_hpkp_db_deinit(wget_hpkp_db *hpkp_db)
{
	if (plugin_vtable) {
		plugin_vtable->deinit(hpkp_db);
		return;
	}

	if (hpkp_db) {
		xfree(hpkp_db->fname);
		wget_thread_mutex_lock(hpkp_db->mutex);
		wget_hashmap_free(&hpkp_db->entries);
		wget_thread_mutex_unlock(hpkp_db->mutex);

		wget_thread_mutex_destroy(&hpkp_db->mutex);
	}
}

/**
 * \param[in] hpkp_db Pointer to the pointer of an HPKP database
 *
 * Closes and frees the HPKP database. A double pointer is required because this function will
 * set the handle (pointer) to the HPKP database to NULL to prevent potential use-after-free conditions.
 *
 * Newly added entries will be lost unless committed to persistent storage using wget_hsts_db_save().
 *
 * If \p hpkp_db or the pointer it points to is NULL then this function does nothing.
 */
void wget_hpkp_db_free(wget_hpkp_db **hpkp_db)
{
	if (plugin_vtable) {
		plugin_vtable->free(hpkp_db);
		return;
	}

	if (hpkp_db && *hpkp_db) {
		wget_hpkp_db_deinit(*hpkp_db);
		xfree(*hpkp_db);
	}
}

/**
 * \param[in] hpkp_db An HPKP database
 * \param[in] host The hostname in question.
 * \param[in] pubkey The public key in DER format
 * \param[in] pubkeysize Size of `pubkey`
 * \return  1 if both host and public key was found in the database,
 *         -2 if host was found and public key was not found,
 *          0 if host was not found,
 *         -1 for any other error condition.
 *
 * Checks the validity of the given hostname and public key combination.
 *
 * This function is thread-safe and can be called from multiple threads concurrently.
 * Any implementation for this function must be thread-safe as well.
 */
int wget_hpkp_db_check_pubkey(wget_hpkp_db *hpkp_db, const char *host, const void *pubkey, size_t pubkeysize)
{
	if (plugin_vtable)
		return plugin_vtable->check_pubkey(hpkp_db, host, pubkey, pubkeysize);

	wget_hpkp *hpkp = NULL;
	int subdomain = 0;
	char digest[32];
	size_t digestlen = wget_hash_get_len(WGET_DIGTYPE_SHA256);

	if (digestlen > sizeof(digest)) {
		error_printf(_("%s: Unexpected hash len %zu > %zu\n"), __func__, digestlen, sizeof(digest));
		return -1;
	}

	for (const char *domain = host; *domain && !hpkp; domain = strchrnul(domain, '.')) {
		while (*domain == '.')
			domain++;

		wget_hpkp key = { .host = domain };

		if (!wget_hashmap_get(hpkp_db->entries, &key, &hpkp))
			subdomain = 1;
	}

	if (!hpkp)
		return 0; // OK, host is not in database

	if (subdomain && !hpkp->include_subdomains)
		return 0; // OK, found a matching super domain which isn't responsible for <host>

	if (wget_hash_fast(WGET_DIGTYPE_SHA256, pubkey, pubkeysize, digest))
		return -1;

	wget_hpkp_pin pinkey = { .pin = digest, .pinsize = digestlen, .hash_type = "sha256" };

	if (wget_vector_find(hpkp->pins, &pinkey) != -1)
		return 1; // OK, pinned pubkey found

	return -2;
}

/* We 'consume' _hpkp and thus set *_hpkp to NULL, so that the calling function
 * can't access it any more */
/**
 * \param[in] hpkp_db An HPKP database
 * \param[in] hpkp pointer to HPKP database entry (will be set to NULL)
 *
 * Adds an entry to given HPKP database. The entry will replace any entry with same `host` (see wget_hpkp_set_host()).
 * If `maxage` property of `hpkp` is zero, any existing entry with same `host` property will be removed.
 *
 * The database takes the ownership of the HPKP entry and the calling function must not access the entry afterwards.
 *
 * This function is thread-safe and can be called from multiple threads concurrently.
 * Any implementation for this function must be thread-safe as well.
 */
void wget_hpkp_db_add(wget_hpkp_db *hpkp_db, wget_hpkp **_hpkp)
{
	if (plugin_vtable) {
		plugin_vtable->add(hpkp_db, _hpkp);
		*_hpkp = NULL;
		return;
	}

	if (!_hpkp || !*_hpkp)
		return;

	wget_hpkp *hpkp = *_hpkp;

	wget_thread_mutex_lock(hpkp_db->mutex);

	if (hpkp->maxage == 0 || wget_vector_size(hpkp->pins) == 0) {
		if (wget_hashmap_remove(hpkp_db->entries, hpkp))
			debug_printf("removed HPKP %s\n", hpkp->host);
		wget_hpkp_free(hpkp);
	} else {
		wget_hpkp *old;

		if (wget_hashmap_get(hpkp_db->entries, hpkp, &old)) {
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
			wget_hashmap_put(hpkp_db->entries, hpkp, hpkp);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(hpkp_db->mutex);

	*_hpkp = NULL;
}

static int hpkp_db_load(wget_hpkp_db *hpkp_db, FILE *fp)
{
	int64_t created, max_age;
	long long _created, _max_age;
	int include_subdomains;

	wget_hpkp *hpkp = NULL;
	struct stat st;
	char *buf = NULL;
	size_t bufsize = 0;
	ssize_t buflen;
	char hash_type[32], host[256], pin_b64[256];
	int64_t now = time(NULL);

	// if the database file hasn't changed since the last read
	// there's no need to reload

	if (fstat(fileno(fp), &st) == 0) {
		if (st.st_mtime != hpkp_db->load_time)
			hpkp_db->load_time = st.st_mtime;
		else
			return 0;
	}

	while ((buflen = wget_getline(&buf, &bufsize, fp)) >= 0) {
		char *linep = buf;

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
				created = _created;
				max_age = _max_age;
				if (created < 0 || max_age < 0 || created >= INT64_MAX / 2 || max_age >= INT64_MAX / 2) {
					max_age = 0; // avoid integer overflow here
				}
				int64_t expires = created + max_age;
				if (max_age && expires >= now) {
					hpkp = wget_hpkp_new();
					if (hpkp) {
						if (!(hpkp->host = wget_strdup(host)))
							xfree(hpkp);
						else {
							hpkp->maxage = max_age;
							hpkp->created = created;
							hpkp->expires = expires;
							hpkp->include_subdomains = include_subdomains != 0;
						}
					}
				} else
					debug_printf("HPKP: entry '%s' is expired\n", host);
			} else {
				error_printf(_("HPKP: could not parse host line '%s'\n"), buf);
			}
		} else if (hpkp) {
			if (sscanf(linep, "*%31s %255s", hash_type, pin_b64) == 2) {
				wget_hpkp_pin_add(hpkp, hash_type, pin_b64);
			} else {
				error_printf(_("HPKP: could not parse pin line '%s'\n"), buf);
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

/**
 * \param[in] hpkp_db Handle to an HPKP database, obtained with wget_hpkp_db_init()
 * \return 0 on success, or a negative number on error
 *
 * Performs all operations necessary to access the HPKP database entries from persistent storage
 * using wget_hpkp_db_check_pubkey() for example.
 *
 * For databases created by wget_hpkp_db_init() data is loaded from `fname` parameter of wget_hpkp_db_init().
 * If this function cannot correctly parse the whole file, -1 is returned.
 *
 * If `hpkp_db` is NULL then this function returns 0 and does nothing else.
 */
int wget_hpkp_db_load(wget_hpkp_db *hpkp_db)
{
	if (plugin_vtable)
		return plugin_vtable->load(hpkp_db);

	if (!hpkp_db)
		return 0;

	if (!hpkp_db->fname || !*hpkp_db->fname)
		return 0;

	if (wget_update_file(hpkp_db->fname, (wget_update_load_fn *) hpkp_db_load, NULL, hpkp_db)) {
		error_printf(_("Failed to read HPKP data\n"));
		return -1;
	} else {
		debug_printf("Fetched HPKP data from '%s'\n", hpkp_db->fname);
		return 0;
	}
}

static int hpkp_save_pin(void *_fp, void *_pin)
{
	FILE *fp = _fp;
	wget_hpkp_pin *pin = _pin;

	wget_fprintf(fp, "*%s %s\n", pin->hash_type, pin->pin_b64);

	if (ferror(fp))
		return -1;

	return 0;
}

WGET_GCC_NONNULL_ALL
static int hpkp_save(void *_fp, const void *_hpkp, WGET_GCC_UNUSED void *v)
{
	FILE *fp = _fp;
	const wget_hpkp *hpkp = _hpkp;

	if (wget_vector_size(hpkp->pins) == 0)
		debug_printf("HPKP: drop '%s', no PIN entries\n", hpkp->host);
	else if (hpkp->expires < time(NULL))
		debug_printf("HPKP: drop '%s', expired\n", hpkp->host);
	else {
		wget_fprintf(fp, "%s %d %lld %lld\n", hpkp->host, hpkp->include_subdomains, (long long) hpkp->created, (long long) hpkp->maxage);

		if (ferror(fp))
			return -1;

		return wget_vector_browse(hpkp->pins, hpkp_save_pin, fp);
	}

	return 0;
}

static int hpkp_db_save(wget_hpkp_db *hpkp_db, FILE *fp)
{
	wget_hashmap *entries = hpkp_db->entries;

	if (wget_hashmap_size(entries) > 0) {
		fputs("# HPKP 1.0 file\n", fp);
		fputs("#Generated by libwget " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		fputs("#<hostname> <incl. subdomains> <created> <max-age>\n\n", fp);

		if (ferror(fp))
			return -1;

		return wget_hashmap_browse(entries, hpkp_save, fp);
	}

	return 0;
}

/**
 * \param[in] hpkp_db Handle to an HPKP database
 * \return 0 if the operation was successful, negative number in case of error.
 *
 * Saves the current HPKP database to persistent storage
 *
 * In case of databases created by wget_hpkp_db_init(), HPKP entries will be saved into file specified by
 * \p fname parameter of wget_hpkp_db_init(). In case of failure -1 will be returned with errno set.
 *
 * If \p fname is NULL then this function returns -1 and does nothing else.
 */
int wget_hpkp_db_save(wget_hpkp_db *hpkp_db)
{
	if (plugin_vtable)
		return plugin_vtable->save(hpkp_db);

	if (!hpkp_db)
		return -1;

	int size;

	if (!hpkp_db->fname || !*hpkp_db->fname)
		return -1;

	if (wget_update_file(hpkp_db->fname,
			     (wget_update_load_fn *) hpkp_db_load,
			     (wget_update_load_fn *) hpkp_db_save,
			     hpkp_db))
	{
		error_printf(_("Failed to write HPKP file '%s'\n"), hpkp_db->fname);
		return -1;
	}

	if ((size = wget_hashmap_size(hpkp_db->entries)))
		debug_printf("Saved %d HPKP entr%s into '%s'\n", size, size != 1 ? "ies" : "y", hpkp_db->fname);
	else
		debug_printf("No HPKP entries to save. Table is empty.\n");

	return 0;
}

/**
 * \param[in] hpkp_db Older HPKP database already passed to wget_hpkp_db_deinit(), or NULL
 * \param[in] fname Name of the file where the data should be stored, or NULL
 * \return Handle (pointer) to an HPKP database
 *
 * Constructor for the default implementation of HSTS database.
 *
 * This function does no file IO, data is loaded from file specified by `fname` when wget_hpkp_db_load() is called.
 * The entries in the file are subject to sanity checks as if they were added to the HPKP database
 * via wget_hpkp_db_add(). In particular, if an entry is expired due to `creation_time + max_age > cur_time`
 * it will not be added to the database, and a subsequent call to wget_hpkp_db_save() with the same `hpkp_db_priv`
 * handle and file name will overwrite the file without all the expired entries.
 *
 * Since the format of the file might change without notice, hand-crafted files are discouraged.
 * To create an HPKP database file that is guaranteed to be correctly parsed by this function,
 * wget_hpkp_db_save() should be used.
 *
 */
wget_hpkp_db *wget_hpkp_db_init(wget_hpkp_db *hpkp_db, const char *fname)
{
	if (plugin_vtable)
		return plugin_vtable->init(hpkp_db, fname);

	if (!hpkp_db) {
		hpkp_db = wget_calloc(1, sizeof(struct wget_hpkp_db_st));
		if (!hpkp_db)
			return NULL;
	} else
		memset(hpkp_db, 0, sizeof(*hpkp_db));

	if (fname)
		hpkp_db->fname = wget_strdup(fname);
	hpkp_db->entries = wget_hashmap_create(16, (wget_hashmap_hash_fn *) hash_hpkp, (wget_hashmap_compare_fn *) compare_hpkp);
	wget_hashmap_set_key_destructor(hpkp_db->entries, (wget_hashmap_key_destructor *) wget_hpkp_free);

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

/**
 * \param[in] hpkp_db HPKP database created using wget_hpkp_db_init()
 * \param[in] fname Name of the file where the data should be stored, or NULL
 *
 * Changes the file where data should be stored. Works only for databases created by wget_hpkp_db_init().
 * This function does no file IO, data is loaded when wget_hpkp_db_load() is called.
 */
void wget_hpkp_db_set_fname(wget_hpkp_db *hpkp_db, const char *fname)
{
	xfree(hpkp_db->fname);
	hpkp_db->fname = wget_strdup(fname);
}

/**@}*/

/*
 * Copyright (c) 2014 Tim Ruehsen
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
 * OCSP caching routines
 *
 * Changelog
 * 08.01.2015  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Online Certificate Status Protocol (RFC 2560) routines
 * \defgroup libwget-ocsp Online Certificate Status Protocol (RFC 2560) routines
 * @{
 *
 * This is an implementation of RFC 2560.
 */

struct wget_ocsp_db_st {
	const char *
		fname;
	wget_hashmap *
		fingerprints;
	wget_hashmap *
		hosts;
	wget_thread_mutex
		mutex;
};

typedef struct {
	const char *
		key;
	int64_t
		maxage; // expiry time
	int64_t
		mtime; // creation time
	bool
		valid : 1; // 1=valid, 0=revoked
} ocsp_entry;

/// Pointer to the function table
static const wget_ocsp_db_vtable
	*plugin_vtable;

void wget_ocsp_set_plugin(const wget_ocsp_db_vtable *vtable)
{
	plugin_vtable = vtable;
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
WGET_GCC_PURE
static unsigned int hash_ocsp(const ocsp_entry *ocsp)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)ocsp->key; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

WGET_GCC_NONNULL_ALL WGET_GCC_PURE
static int compare_ocsp(const ocsp_entry *h1, const ocsp_entry *h2)
{
	return strcmp(h1->key, h2->key);
}

static ocsp_entry *init_ocsp(ocsp_entry *ocsp)
{
	if (!ocsp) {
		if (!(ocsp = wget_calloc(1, sizeof(ocsp_entry))))
			return NULL;
	} else
		memset(ocsp, 0, sizeof(*ocsp));

	ocsp->mtime = time(NULL);

	return ocsp;
}

static void deinit_ocsp(ocsp_entry *ocsp)
{
	if (ocsp) {
		xfree(ocsp->key);
	}
}

static void free_ocsp(ocsp_entry *ocsp)
{
	if (ocsp) {
		deinit_ocsp(ocsp);
		xfree(ocsp);
	}
}

static ocsp_entry *new_ocsp(const char *fingerprint, int64_t maxage, bool valid)
{
	if (fingerprint) {
		if (!(fingerprint = wget_strdup(fingerprint)))
			return NULL;
	}

	ocsp_entry *ocsp = init_ocsp(NULL);

	if (ocsp) {
		ocsp->key = fingerprint;
		ocsp->maxage = maxage;
		ocsp->valid = valid;
	} else
		xfree(fingerprint);

	return ocsp;
}

/**
 * \param[in] ocsp_db an OCSP database
 * \param[in] fingerprint The public key fingerprint to search for
 * \param[out] revoked If the key is found, the value will be set to 1 if the key has been revoked,
 *                     zero if not. If the key is not found, the value is unmodified.
 * \return %true if the fingerprint was found, %false otherwise.
 *
 * Searches for a cached OCSP response in the OCSP database. OCSP responses are added using
 * wget_ocsp_db_add_fingerprint().
 *
 * If `ocsp_db` is NULL then this function returns 0 and does nothing else.
 *
 * This function is thread-safe and can be called from multiple threads concurrently.
 * Any implementation for this function must be thread-safe as well.
 */
bool wget_ocsp_fingerprint_in_cache(const wget_ocsp_db *ocsp_db, const char *fingerprint, int *revoked)
{
	if (plugin_vtable)
		return plugin_vtable->fingerprint_in_cache(ocsp_db, fingerprint, revoked);

	if (!ocsp_db)
		return false;

	ocsp_entry ocsp, *ocspp;

	// look for an exact match
	ocsp.key = fingerprint;
	if (wget_hashmap_get(ocsp_db->fingerprints, &ocsp, &ocspp) && ocspp->maxage >= (int64_t) time(NULL)) {
		if (revoked)
			*revoked = !ocspp->valid;
		return true;
	}

	return false;
}

/**
 * \param[in] ocsp_db an OCSP database
 * \param[in] hostname The host to search found.
 * \return 1 if a valid host entry was found, 0 otherwise
 *
 * Checks if there exists an entry for the given host added by wget_ocsp_db_add_host() which has not expired.
 *
 * If `ocsp_db` is NULL then this function returns 0 and does nothing else.
 *
 * This function is thread-safe and can be called from multiple threads concurrently.
 * Any implementation for this function must be thread-safe as well.
 *
 * \see wget_ocsp_db_add_host
 */
bool wget_ocsp_hostname_is_valid(const wget_ocsp_db *ocsp_db, const char *hostname)
{
	if (plugin_vtable)
		return plugin_vtable->hostname_is_valid(ocsp_db, hostname);

	if (!ocsp_db)
		return false;

	ocsp_entry ocsp, *ocspp;

	// look for an exact match
	ocsp.key = hostname;
	if (wget_hashmap_get(ocsp_db->hosts, &ocsp, &ocspp) && ocspp->maxage >= (int64_t) time(NULL)) {
		return true;
	}

	return false;
}

/**
 * \param[in] ocsp_db an OCSP database
 *
 * Frees all resources allocated for the OCSP database, except for the structure.
 * Works only for databases created by wget_ocsp_db_init().
 * `ocsp_db` can then be passed to \ref wget_ocsp_db_init "wget_ocsp_db_init()".
 *
 * If `ocsp_db` is NULL then this function does nothing.
 */
void wget_ocsp_db_deinit(wget_ocsp_db *ocsp_db)
{
	if (plugin_vtable) {
		plugin_vtable->deinit(ocsp_db);
		return;
	}

	if (ocsp_db) {
		xfree(ocsp_db->fname);
		wget_thread_mutex_lock(ocsp_db->mutex);
		wget_hashmap_free(&ocsp_db->fingerprints);
		wget_hashmap_free(&ocsp_db->hosts);
		wget_thread_mutex_unlock(ocsp_db->mutex);

		wget_thread_mutex_destroy(&ocsp_db->mutex);
	}
}

/**
 * \param[in] ocsp_db pointer to an OCSP database handle
 *
 * Frees all resources allocated for the OCSP database.
 *
 * A double pointer is required because this function will set the handle (pointer) to the HPKP database to NULL
 * to prevent potential use-after-free conditions.
 *
 * New entries added to the database will be lost unless committed to the persistent storage using
 * wget_ocsp_db_save().
 *
 * If `ocsp_db` or the pointer it points to is NULL, then this function does nothing.
 */
void wget_ocsp_db_free(wget_ocsp_db **ocsp_db)
{
	if (plugin_vtable) {
		plugin_vtable->free(ocsp_db);
		return;
	}

	if (ocsp_db && *ocsp_db) {
		wget_ocsp_db_deinit(*ocsp_db);
		xfree(*ocsp_db);
	}
}

static void ocsp_db_add_fingerprint_entry(wget_ocsp_db *ocsp_db, ocsp_entry *ocsp)
{
	if (!ocsp)
		return;

	if (!ocsp_db) {
		free_ocsp(ocsp);
		return;
	}

	wget_thread_mutex_lock(ocsp_db->mutex);

	if (ocsp->maxage == 0) {
		if (wget_hashmap_remove(ocsp_db->fingerprints, ocsp))
			debug_printf("removed OCSP cert %s\n", ocsp->key);
		free_ocsp(ocsp);
	} else {
		ocsp_entry *old;

		if (wget_hashmap_get(ocsp_db->fingerprints, ocsp, &old)) {
			if (old->mtime < ocsp->mtime) {
				old->mtime = ocsp->mtime;
				old->maxage = ocsp->maxage;
				old->valid = ocsp->valid;
				debug_printf("update OCSP cert %s (maxage=%lld,valid=%d)\n", old->key, (long long)old->maxage, old->valid);
			}
			free_ocsp(ocsp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'ocsp'
			debug_printf("add OCSP cert %s (maxage=%lld,valid=%d)\n", ocsp->key, (long long)ocsp->maxage, ocsp->valid);
			wget_hashmap_put(ocsp_db->fingerprints, ocsp, ocsp);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(ocsp_db->mutex);
}

/**
 * \param[in] ocsp_db an OCSP database
 * \param[in] fingerprint Public key fingerprint
 * \param[in] maxage The time till which this entry should be considered valid (in seconds from epoch),
 *                   or 0 to remove existing entry.
 * \param[in] valid Whether the public key is valid according to the OCSP responder
 *
 * Adds an OCSP response into the OCSP database. The new entry replaces any existing entry with same
 * `fingerprint`. If `maxage` is 0, any entry with matching `fingerprint` is removed.
 *
 * If `ocsp_db` is NULL then this function does nothing.
 *
 * This function is thread-safe and can be called from multiple threads concurrently.
 * Any implementation for this function must be thread-safe as well.
 */
void wget_ocsp_db_add_fingerprint(wget_ocsp_db *ocsp_db, const char *fingerprint, int64_t maxage, bool valid)
{
	if (plugin_vtable) {
		plugin_vtable->add_fingerprint(ocsp_db, fingerprint, maxage, valid);
		return;
	}

	ocsp_entry *ocsp = new_ocsp(fingerprint, maxage, valid);

	ocsp_db_add_fingerprint_entry(ocsp_db, ocsp);
}

static void ocsp_db_add_host_entry(wget_ocsp_db *ocsp_db, ocsp_entry *ocsp)
{
	if (!ocsp)
		return;

	if (!ocsp_db) {
		free_ocsp(ocsp);
		return;
	}

	wget_thread_mutex_lock(ocsp_db->mutex);

	if (ocsp->maxage == 0) {
		if (wget_hashmap_remove(ocsp_db->hosts, ocsp))
			debug_printf("removed OCSP host %s\n", ocsp->key);
		free_ocsp(ocsp);
	} else {
		ocsp_entry *old;

		if (wget_hashmap_get(ocsp_db->hosts, ocsp, &old)) {
			if (old->mtime < ocsp->mtime) {
				old->mtime = ocsp->mtime;
				old->maxage = ocsp->maxage;
				old->valid = ocsp->valid;
				debug_printf("update OCSP host %s (maxage=%lld)\n", old->key, (long long)old->maxage);
			}
			free_ocsp(ocsp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'ocsp'
			wget_hashmap_put(ocsp_db->hosts, ocsp, ocsp);
			debug_printf("add OCSP host %s (maxage=%lld)\n", ocsp->key, (long long)ocsp->maxage);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(ocsp_db->mutex);
}

/**
 * \param[in] ocsp_db an OCSP database
 * \param[in] host The host to add
 * \param[in] maxage The time till which this entry should be considered valid (in seconds from epoch),
 *                   or 0 to remove existing entry.
 *
 * Adds a host entry into the given OCSP database. The new entry replaces any existing entry with same
 * `host`. If `maxage` is 0, any entry with matching `host` is removed.
 *
 * The intended use is to serve as a cache for hosts with certificate chains for  which all OCSP responses are positive.
 * The added entries can then be queried for by wget_ocsp_hostname_is_valid(). A positive response indicates
 * fingerprints for each public key in the certificate chain are likely already added to the database, in which
 * case OCSP responses are not needed.
 *
 * If `ocsp_db` is NULL then this function does nothing.
 *
 * This function is thread-safe and can be called from multiple threads concurrently.
 * Any implementation for this function must be thread-safe as well.
 */
void wget_ocsp_db_add_host(wget_ocsp_db *ocsp_db, const char *host, int64_t maxage)
{
	if (plugin_vtable) {
		plugin_vtable->add_host(ocsp_db, host, maxage);
		return;
	}

	ocsp_entry *ocsp = new_ocsp(host, maxage, false);

	ocsp_db_add_host_entry(ocsp_db, ocsp);
}

// load the OCSP cache from a flat file
// not thread-save

static int ocsp_db_load(wget_ocsp_db *ocsp_db, FILE *fp, bool load_hosts)
{
	ocsp_entry ocsp;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	int64_t now = time(NULL);
	int ok;

	while ((buflen = wget_getline(&buf, &bufsize, fp)) >= 0) {
		linep = buf;

		while (isspace(*linep)) linep++; // ignore leading whitespace
		if (!*linep) continue; // skip empty lines

		if (*linep == '#')
			continue; // skip comments

		// strip off \r\n
		while (buflen > 0 && (buf[buflen] == '\n' || buf[buflen] == '\r'))
			buf[--buflen] = 0;

		init_ocsp(&ocsp);
		ok = 0;

		// parse cert's sha-256 checksum
		if (*linep) {
			for (p = linep; *linep && !isspace(*linep);) linep++;
			ocsp.key = wget_strmemdup(p, linep - p);
		}

		// parse max age
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep);) linep++;
			ocsp.maxage = (int64_t) atoll(p);
			if (ocsp.maxage < now) {
				// drop expired entry
				deinit_ocsp(&ocsp);
				continue;
			}
			ok = 1;
		}

		// parse mtime (age of this entry)
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep);) linep++;
			ocsp.mtime = (int64_t) atoll(p);
		}

		// parse mtime (age of this entry)
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep);) linep++;
			ocsp.valid = atoi(p) != 0;
		}

		if (ok) {
			if (load_hosts)
				ocsp_db_add_host_entry(ocsp_db, wget_memdup(&ocsp, sizeof(ocsp)));
			else
				ocsp_db_add_fingerprint_entry(ocsp_db, wget_memdup(&ocsp, sizeof(ocsp)));
		} else {
			deinit_ocsp(&ocsp);
			error_printf(_("Failed to parse OCSP line: '%s'\n"), buf);
		}
	}

	xfree(buf);

	if (ferror(fp))
		return -1;

	return 0;
}

static int ocsp_db_load_hosts(void *ocsp_db, FILE *fp)
{
	return ocsp_db_load(ocsp_db, fp, true);
}

static int ocsp_db_load_fingerprints(void *ocsp_db, FILE *fp)
{
	return ocsp_db_load(ocsp_db, fp, false);
}

/**
 * \param[in] ocsp_db An OCSP database
 * \return 0 if the operation was successful, a negative number in case of error
 *
 * Performs all necessary operations for accessing OCSP database entries from the persistent storage.
 *
 * For databases created by wget_ocsp_db_init(), the data is fetched from file specified by `fname` parameter
 * of wget_ocsp_db_load().
 *
 * If `ocsp_db` is NULL then this function returns -1 and does nothing else.
 */
int wget_ocsp_db_load(wget_ocsp_db *ocsp_db)
{
	if (plugin_vtable)
		return plugin_vtable->load(ocsp_db);

	int ret;

	if (!ocsp_db->fname || !*ocsp_db->fname)
		return -1;

	char *fname_hosts = wget_aprintf("%s_hosts", ocsp_db->fname);

	if ((ret = wget_update_file(fname_hosts, ocsp_db_load_hosts, NULL, ocsp_db)))
		error_printf(_("Failed to read OCSP hosts\n"));
	else
		debug_printf("Fetched OCSP hosts from '%s'\n", fname_hosts);

	xfree(fname_hosts);

	if (wget_update_file(ocsp_db->fname, ocsp_db_load_fingerprints, NULL, ocsp_db)) {
		error_printf(_("Failed to read OCSP fingerprints\n"));
		ret = -1;
	} else
		debug_printf("Fetched OCSP fingerprints from '%s'\n", ocsp_db->fname);

	return ret;
}

WGET_GCC_NONNULL_ALL
static int ocsp_save_fingerprint(void *_fp, const void *_ocsp, WGET_GCC_UNUSED void *v)
{
	FILE *fp = _fp;
	const ocsp_entry *ocsp = _ocsp;

	wget_fprintf(fp, "%s %lld %lld %d\n", ocsp->key, (long long)ocsp->maxage, (long long)ocsp->mtime, ocsp->valid);
	return 0;
}

WGET_GCC_NONNULL_ALL
static int ocsp_save_host(void *_fp, const void *_ocsp, WGET_GCC_UNUSED void *v)
{
	FILE *fp = _fp;
	const ocsp_entry *ocsp = _ocsp;

	wget_fprintf(fp, "%s %lld %lld\n", ocsp->key, (long long)ocsp->maxage, (long long)ocsp->mtime);
	return 0;
}

static int ocsp_db_save_hosts(void *ocsp_db, FILE *fp)
{
	wget_hashmap *map = ((wget_ocsp_db *) ocsp_db)->hosts;

	if ((wget_hashmap_size(map)) > 0) {
		fputs("#OCSP 1.0 host file\n", fp);
		fputs("#Generated by libwget " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		fputs("<hostname> <time_t maxage> <time_t mtime>\n\n", fp);
		wget_hashmap_browse(map, ocsp_save_host, fp);

		if (ferror(fp))
			return -1;
	}

	return 0;
}

static int ocsp_db_save_fingerprints(void *ocsp_db, FILE *fp)
{
	wget_hashmap *map = ((wget_ocsp_db *) ocsp_db)->fingerprints;

	if ((wget_hashmap_size(map)) > 0) {

		fputs("#OCSP 1.0 fingerprint file\n", fp);
		fputs("#Generated by Wget " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		fputs("<sha256 fingerprint of cert> <time_t maxage> <time_t mtime> <valid>\n\n", fp);
		wget_hashmap_browse(map, ocsp_save_fingerprint, fp);

		if (ferror(fp))
			return -1;
	}

	return 0;
}

/**
 * \param[in] ocsp_db An OCSP database
 * \return 0 if the operation was successful, a negative number in case of error
 *
 * Stores all changes to the OCSP database to persistent storage.
 *
 * For databases created by wget_ocsp_db_init(), the data is stored into file specified by `fname` parameter
 * of wget_ocsp_db_load(), overwriting any existing content.
 *
 * If `ocsp_db` is NULL then this function returns -1 and does nothing else.
 */
int wget_ocsp_db_save(wget_ocsp_db *ocsp_db)
{
	if (plugin_vtable)
		return plugin_vtable->save(ocsp_db);

	int ret;

	if (!ocsp_db || !ocsp_db->fname || !*ocsp_db->fname)
		return -1;

	char *fname_hosts = wget_aprintf("%s_hosts", ocsp_db->fname);

	if ((ret = wget_update_file(fname_hosts, ocsp_db_load_hosts, ocsp_db_save_hosts, ocsp_db)))
		error_printf(_("Failed to write to OCSP hosts to '%s'\n"), fname_hosts);
	else
		debug_printf("Saved OCSP hosts to '%s'\n", fname_hosts);

	xfree(fname_hosts);

	if (wget_update_file(ocsp_db->fname, ocsp_db_load_fingerprints, ocsp_db_save_fingerprints, ocsp_db)) {
		error_printf(_("Failed to write to OCSP fingerprints to '%s'\n"), ocsp_db->fname);
		ret = -1;
	} else
		debug_printf("Saved OCSP fingerprints to '%s'\n", ocsp_db->fname);

	return ret;
}

/**
 * \param[in] ocsp_db OCSP database handle previously passed to wget_ocsp_db_deinit(), or NULL
 * \param[in] fname The filename from where OCSP entries should be loaded, or NULL
 * \return A new OCSP database
 *
 * Constructor for default implementation of OCSP database.
 *
 * This function does no file IO, OCSP entries are read from `fname` into memory when wget_ocsp_db_load() is called.
 */
wget_ocsp_db *wget_ocsp_db_init(wget_ocsp_db *ocsp_db, const char *fname)
{
	if (plugin_vtable)
		return plugin_vtable->init(ocsp_db, fname);

	if (fname)
		if (!(fname = wget_strdup(fname)))
			return NULL;

	wget_hashmap *fingerprints = wget_hashmap_create(16, (wget_hashmap_hash_fn *) hash_ocsp, (wget_hashmap_compare_fn *) compare_ocsp);
	wget_hashmap *hosts = wget_hashmap_create(16, (wget_hashmap_hash_fn *) hash_ocsp, (wget_hashmap_compare_fn *) compare_ocsp);

	if (!fingerprints || !hosts) {
no_mem:
		wget_hashmap_free(&hosts);
		wget_hashmap_free(&fingerprints);
		xfree(fname);
		return NULL;
	}

	if (!ocsp_db) {
		if (!(ocsp_db = wget_calloc(1, sizeof(struct wget_ocsp_db_st))))
			goto no_mem;
	} else
		memset(ocsp_db, 0, sizeof(*ocsp_db));

	ocsp_db->fname = fname;

	wget_hashmap_set_key_destructor(fingerprints, (wget_hashmap_key_destructor *) free_ocsp);
	wget_hashmap_set_value_destructor(fingerprints, (wget_hashmap_value_destructor *) free_ocsp);
	ocsp_db->fingerprints = fingerprints;

	wget_hashmap_set_key_destructor(hosts, (wget_hashmap_key_destructor *) free_ocsp);
	wget_hashmap_set_value_destructor(hosts, (wget_hashmap_value_destructor *) free_ocsp);
	ocsp_db->hosts = hosts;

	wget_thread_mutex_init(&ocsp_db->mutex);

	return (wget_ocsp_db *) ocsp_db;
}

/**
 * \param[in] ocsp_db an OCSP database
 * \param[in] fname The filename from where OCSP entries should be loaded, or NULL
 *
 * Changes the file from where OCSP database entries would be loaded or saved.
 * Works only with OCSP databases created with wget_ocsp_db_init().
 */
void wget_ocsp_db_set_fname(wget_ocsp_db *ocsp_db, const char *fname)
{
	xfree(ocsp_db->fname);
	ocsp_db->fname = wget_strdup(fname);
}

/**@}*/

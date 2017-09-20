/*
 * Copyright(c) 2014 Tim Ruehsen
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

typedef struct {
	wget_ocsp_db_t
		parent;
	char *
		fname;
	wget_hashmap_t *
		fingerprints;
	wget_hashmap_t *
		hosts;
	wget_thread_mutex_t
		mutex;
} _ocsp_db_impl_t;

typedef struct {
	const char *
		key;
	int64_t
		maxage; // expiry time
	int64_t
		mtime; // creation time
	bool
		valid : 1; // 1=valid, 0=revoked
} _ocsp_t;

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int G_GNUC_WGET_PURE _hash_ocsp(const _ocsp_t *ocsp)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)ocsp->key; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static int G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PURE _compare_ocsp(const _ocsp_t *h1, const _ocsp_t *h2)
{
	return strcmp(h1->key, h2->key);
}

static _ocsp_t *_init_ocsp(_ocsp_t *ocsp)
{
	if (!ocsp)
		ocsp = xmalloc(sizeof(_ocsp_t));

	memset(ocsp, 0, sizeof(*ocsp));
	ocsp->mtime = time(NULL);

	return ocsp;
}

static void _deinit_ocsp(_ocsp_t *ocsp)
{
	if (ocsp) {
		xfree(ocsp->key);
	}
}

static void _free_ocsp(_ocsp_t *ocsp)
{
	if (ocsp) {
		_deinit_ocsp(ocsp);
		xfree(ocsp);
	}
}

static _ocsp_t *_new_ocsp(const char *fingerprint, time_t maxage, int valid)
{
	_ocsp_t *ocsp = _init_ocsp(NULL);

	ocsp->key = wget_strdup(fingerprint);
	ocsp->maxage = maxage;
	ocsp->valid = !!valid;

	return ocsp;
}

/**
 * \param[in] ocsp_db an OCSP database
 * \param[in] fingerprint The public key fingerprint to search for
 * \param[out] revoked If the key is found, the value will be set to 1 if the key has been revoked,
 *                     zero if not. If the key is not found, the value is unmodified.
 * \return 1 if the fingerprint was found, 0 otherwise.
 *
 * Searches for a cached OCSP response in the OCSP database. OCSP responses are added using
 * wget_ocsp_db_add_fingerprint().
 *
 * If `ocsp_db` is NULL then this function returns 0 and does nothing else.
 *
 * This function is thread-safe and can be called from multiple threads concurrently.
 * Any implementation for this function must be thread-safe as well.
 */
int wget_ocsp_fingerprint_in_cache(const wget_ocsp_db_t *ocsp_db, const char *fingerprint, int *revoked)
{
	if (ocsp_db)
		return ocsp_db->vtable->fingerprint_in_cache(ocsp_db, fingerprint, revoked);

	return 0;
}
static bool impl_ocsp_db_fingerprint_in_cache(const wget_ocsp_db_t *ocsp_db, const char *fingerprint, int *revoked)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	_ocsp_t ocsp, *ocspp;

	// look for an exact match
	ocsp.key = fingerprint;
	if ((ocspp = wget_hashmap_get(ocsp_db_priv->fingerprints, &ocsp)) && ocspp->maxage >= (int64_t) time(NULL)) {
		if (revoked)
			*revoked = !ocspp->valid;
		return 1;
	}

	return 0;
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
bool wget_ocsp_hostname_is_valid(const wget_ocsp_db_t *ocsp_db, const char *hostname)
{
	if (ocsp_db)
		return ocsp_db->vtable->hostname_is_valid(ocsp_db, hostname);

	return 0;
}
static bool impl_ocsp_db_hostname_is_valid(const wget_ocsp_db_t *ocsp_db, const char *hostname)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	_ocsp_t ocsp, *ocspp;

	// look for an exact match
	ocsp.key = hostname;
	if ((ocspp = wget_hashmap_get(ocsp_db_priv->hosts, &ocsp)) && ocspp->maxage >= (int64_t) time(NULL)) {
		return 1;
	}

	return 0;
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
void wget_ocsp_db_deinit(wget_ocsp_db_t *ocsp_db)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	if (ocsp_db_priv) {
		xfree(ocsp_db_priv->fname);
		wget_thread_mutex_lock(&ocsp_db_priv->mutex);
		wget_hashmap_free(&ocsp_db_priv->fingerprints);
		wget_hashmap_free(&ocsp_db_priv->hosts);
		wget_thread_mutex_unlock(&ocsp_db_priv->mutex);
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
 * New entries added to the database will be lost unless commited to the persistent storage using
 * wget_ocsp_db_save().
 *
 * If `ocsp_db` or the pointer it points to is NULL, then this function does nothing.
 */
void wget_ocsp_db_free(wget_ocsp_db_t **ocsp_db)
{
	if (! ocsp_db || ! *ocsp_db)
		return;

	(*ocsp_db)->vtable->free(*ocsp_db);
	*ocsp_db = NULL;
}
static void impl_ocsp_db_free(wget_ocsp_db_t *ocsp_db)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	wget_ocsp_db_deinit((wget_ocsp_db_t *) ocsp_db_priv);
	xfree(ocsp_db_priv);
}

static void _ocsp_db_add_fingerprint_entry(_ocsp_db_impl_t *ocsp_db_priv, _ocsp_t *ocsp)
{
	if (!ocsp)
		return;

	if (!ocsp_db_priv) {
		_free_ocsp(ocsp);
		return;
	}

	wget_thread_mutex_lock(&ocsp_db_priv->mutex);

	if (ocsp->maxage == 0) {
		if (wget_hashmap_remove(ocsp_db_priv->fingerprints, ocsp))
			debug_printf("removed OCSP cert %s\n", ocsp->key);
		_free_ocsp(ocsp);
	} else {
		_ocsp_t *old = wget_hashmap_get(ocsp_db_priv->fingerprints, ocsp);

		if (old) {
			if (old->mtime < ocsp->mtime) {
				old->mtime = ocsp->mtime;
				old->maxage = ocsp->maxage;
				old->valid = ocsp->valid;
				debug_printf("update OCSP cert %s (maxage=%lld,valid=%d)\n", old->key, (long long)old->maxage, old->valid);
			}
			_free_ocsp(ocsp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'ocsp'
			debug_printf("add OCSP cert %s (maxage=%lld,valid=%d)\n", ocsp->key, (long long)ocsp->maxage, ocsp->valid);
			wget_hashmap_put_noalloc(ocsp_db_priv->fingerprints, ocsp, ocsp);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(&ocsp_db_priv->mutex);
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
void wget_ocsp_db_add_fingerprint(wget_ocsp_db_t *ocsp_db, const char *fingerprint, time_t maxage, int valid)
{
	if (ocsp_db)
		ocsp_db->vtable->add_fingerprint(ocsp_db, fingerprint, maxage, valid);
}
static void impl_ocsp_db_add_fingerprint(wget_ocsp_db_t *ocsp_db, const char *fingerprint, time_t maxage, int valid)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	_ocsp_t *ocsp = _new_ocsp(fingerprint, maxage, valid);

	_ocsp_db_add_fingerprint_entry(ocsp_db_priv, ocsp);
}

static void _ocsp_db_add_host_entry(_ocsp_db_impl_t *ocsp_db_priv, _ocsp_t *ocsp)
{
	if (!ocsp)
		return;

	if (!ocsp_db_priv) {
		_free_ocsp(ocsp);
		return;
	}

	wget_thread_mutex_lock(&ocsp_db_priv->mutex);

	if (ocsp->maxage == 0) {
		if (wget_hashmap_remove(ocsp_db_priv->hosts, ocsp))
			debug_printf("removed OCSP host %s\n", ocsp->key);
		_free_ocsp(ocsp);
	} else {
		_ocsp_t *old = wget_hashmap_get(ocsp_db_priv->hosts, ocsp);

		if (old) {
			if (old->mtime < ocsp->mtime) {
				old->mtime = ocsp->mtime;
				old->maxage = ocsp->maxage;
				old->valid = ocsp->valid;
				debug_printf("update OCSP host %s (maxage=%lld)\n", old->key, (long long)old->maxage);
			}
			_free_ocsp(ocsp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'ocsp'
			wget_hashmap_put_noalloc(ocsp_db_priv->hosts, ocsp, ocsp);
			debug_printf("add OCSP host %s (maxage=%lld)\n", ocsp->key, (long long)ocsp->maxage);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(&ocsp_db_priv->mutex);
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
void wget_ocsp_db_add_host(wget_ocsp_db_t *ocsp_db, const char *host, time_t maxage)
{
	if (ocsp_db)
		ocsp_db->vtable->add_host(ocsp_db, host, maxage);
}
static void impl_ocsp_db_add_host(wget_ocsp_db_t *ocsp_db, const char *host, time_t maxage)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	_ocsp_t *ocsp = _new_ocsp(host, maxage, 0);

	_ocsp_db_add_host_entry(ocsp_db_priv, ocsp);
}

// load the OCSP cache from a flat file
// not thread-save

static int _ocsp_db_load(_ocsp_db_impl_t *ocsp_db_priv, FILE *fp, int load_hosts)
{
	_ocsp_t ocsp;
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

		_init_ocsp(&ocsp);
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
				_deinit_ocsp(&ocsp);
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
			ocsp.valid = !!atoi(p);
		}

		if (ok) {
			if (load_hosts)
				_ocsp_db_add_host_entry(ocsp_db_priv, wget_memdup(&ocsp, sizeof(ocsp)));
			else
				_ocsp_db_add_fingerprint_entry(ocsp_db_priv, wget_memdup(&ocsp, sizeof(ocsp)));
		} else {
			_deinit_ocsp(&ocsp);
			error_printf(_("Failed to parse OCSP line: '%s'\n"), buf);
		}
	}

	xfree(buf);

	if (ferror(fp))
		return -1;

	return 0;
}

static int _ocsp_db_load_hosts(void *ocsp_db_priv, FILE *fp)
{
	return _ocsp_db_load(ocsp_db_priv, fp, 1);
}

static int _ocsp_db_load_fingerprints(void *ocsp_db_priv, FILE *fp)
{
	return _ocsp_db_load(ocsp_db_priv, fp, 0);
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
int wget_ocsp_db_load(wget_ocsp_db_t *ocsp_db)
{
	if (ocsp_db)
		return ocsp_db->vtable->load(ocsp_db);

	return -1;
}
static int impl_ocsp_db_load(wget_ocsp_db_t *ocsp_db)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	int ret;

	if (!ocsp_db_priv->fname || !*ocsp_db_priv->fname)
		return -1;

	char fname_hosts[strlen(ocsp_db_priv->fname) + 6 + 1];
	snprintf(fname_hosts, sizeof(fname_hosts), "%s_hosts", ocsp_db_priv->fname);

	if ((ret = wget_update_file(fname_hosts, _ocsp_db_load_hosts, NULL, ocsp_db_priv)))
		error_printf(_("Failed to read OCSP hosts\n"));
	else
		debug_printf(_("Fetched OCSP hosts from '%s'\n"), fname_hosts);

	if (wget_update_file(ocsp_db_priv->fname, _ocsp_db_load_fingerprints, NULL, ocsp_db_priv)) {
		error_printf(_("Failed to read OCSP fingerprints\n"));
		ret = -1;
	} else
		debug_printf(_("Fetched OCSP fingerprints from '%s'\n"), ocsp_db_priv->fname);

	return ret;
}

static int G_GNUC_WGET_NONNULL_ALL _ocsp_save_fingerprint(FILE *fp, const _ocsp_t *ocsp)
{
	fprintf(fp, "%s %lld %lld %d\n", ocsp->key, (long long)ocsp->maxage, (long long)ocsp->mtime, ocsp->valid);
	return 0;
}

static int G_GNUC_WGET_NONNULL_ALL _ocsp_save_host(FILE *fp, const _ocsp_t *ocsp)
{
	fprintf(fp, "%s %lld %lld\n", ocsp->key, (long long)ocsp->maxage, (long long)ocsp->mtime);
	return 0;
}

static int _ocsp_db_save_hosts(void *ocsp_db_priv, FILE *fp)
{
	wget_hashmap_t *map = ((_ocsp_db_impl_t *)ocsp_db_priv)->hosts;

	if ((wget_hashmap_size(map)) > 0) {
		fputs("#OCSP 1.0 host file\n", fp);
		fputs("#Generated by Wget " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		fputs("<hostname> <time_t maxage> <time_t mtime>\n\n", fp);
		wget_hashmap_browse(map, (wget_hashmap_browse_t)_ocsp_save_host, fp);

		if (ferror(fp))
			return -1;
	}

	return 0;
}

static int _ocsp_db_save_fingerprints(void *ocsp_db_priv, FILE *fp)
{
	wget_hashmap_t *map = ((_ocsp_db_impl_t *)ocsp_db_priv)->fingerprints;

	if ((wget_hashmap_size(map)) > 0) {

		fputs("#OCSP 1.0 fingerprint file\n", fp);
		fputs("#Generated by Wget " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		fputs("<sha256 fingerprint of cert> <time_t maxage> <time_t mtime> <valid>\n\n", fp);
		wget_hashmap_browse(map, (wget_hashmap_browse_t)_ocsp_save_fingerprint, fp);

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
int wget_ocsp_db_save(wget_ocsp_db_t *ocsp_db)
{
	if (ocsp_db)
		return ocsp_db->vtable->save(ocsp_db);

	return -1;
}
// Save the OCSP hosts and fingerprints to flat files.
// Protected by flock()
static int impl_ocsp_db_save(wget_ocsp_db_t *ocsp_db)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	int ret;

	if (!ocsp_db_priv || !ocsp_db_priv->fname || !*ocsp_db_priv->fname)
		return -1;

	char fname_hosts[strlen(ocsp_db_priv->fname) + 6 + 1];
	snprintf(fname_hosts, sizeof(fname_hosts), "%s_hosts", ocsp_db_priv->fname);

	if ((ret = wget_update_file(fname_hosts, _ocsp_db_load_hosts, _ocsp_db_save_hosts, ocsp_db_priv)))
		error_printf(_("Failed to write to OCSP hosts to '%s'\n"), fname_hosts);
	else
		debug_printf(_("Saved OCSP hosts to '%s'\n"), fname_hosts);

	if (wget_update_file(ocsp_db_priv->fname, _ocsp_db_load_fingerprints, _ocsp_db_save_fingerprints, ocsp_db_priv)) {
		error_printf(_("Failed to write to OCSP fingerprints to '%s'\n"), ocsp_db_priv->fname);
		ret = -1;
	} else
		debug_printf(_("Saved OCSP fingerprints to '%s'\n"), ocsp_db_priv->fname);

	return ret;
}

static struct wget_ocsp_db_vtable vtable = {
	.load = impl_ocsp_db_load,
	.save = impl_ocsp_db_save,
	.fingerprint_in_cache = impl_ocsp_db_fingerprint_in_cache,
	.hostname_is_valid = impl_ocsp_db_hostname_is_valid,
	.add_fingerprint = impl_ocsp_db_add_fingerprint,
	.add_host = impl_ocsp_db_add_host,
	.free = impl_ocsp_db_free
};

/**
 * \param[in] ocsp_db OCSP database handle previously passed to wget_ocsp_db_deinit(), or NULL
 * \param[in] fname The filename from where OCSP entries should be loaded, or NULL
 * \return A new OCSP database
 *
 * Constructor for default implementation of OCSP database.
 *
 * This function does no file IO, OCSP entries are read from `fname` into memory when wget_ocsp_db_load() is called.
 */
wget_ocsp_db_t *wget_ocsp_db_init(wget_ocsp_db_t *ocsp_db, const char *fname)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	if (!ocsp_db_priv)
		ocsp_db_priv = xmalloc(sizeof(_ocsp_db_impl_t));

	memset(ocsp_db_priv, 0, sizeof(*ocsp_db_priv));

	ocsp_db_priv->parent.vtable = &vtable;
	if (fname)
		ocsp_db_priv->fname = wget_strdup(fname);
	ocsp_db_priv->fingerprints = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_ocsp, (wget_hashmap_compare_t)_compare_ocsp);
	wget_hashmap_set_key_destructor(ocsp_db_priv->fingerprints, (wget_hashmap_key_destructor_t)_free_ocsp);
	wget_hashmap_set_value_destructor(ocsp_db_priv->fingerprints, (wget_hashmap_value_destructor_t)_free_ocsp);

	ocsp_db_priv->hosts = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_ocsp, (wget_hashmap_compare_t)_compare_ocsp);
	wget_hashmap_set_key_destructor(ocsp_db_priv->hosts, (wget_hashmap_key_destructor_t)_free_ocsp);
	wget_hashmap_set_value_destructor(ocsp_db_priv->hosts, (wget_hashmap_value_destructor_t)_free_ocsp);

	wget_thread_mutex_init(&ocsp_db_priv->mutex);

	return (wget_ocsp_db_t *) ocsp_db_priv;
}

/**
 * \param[in] ocsp_db an OCSP database
 * \param[in] fname The filename from where OCSP entries should be loaded, or NULL
 *
 * Changes the file from where OCSP database entries would be loaded or saved.
 * Works only with OCSP databases created with wget_ocsp_db_init().
 */
void wget_ocsp_db_set_fname(wget_ocsp_db_t *ocsp_db, const char *fname)
{
	_ocsp_db_impl_t *ocsp_db_priv = (_ocsp_db_impl_t *) ocsp_db;

	xfree(ocsp_db_priv->fname);
	if (fname)
		ocsp_db_priv->fname = wget_strdup(fname);
}

/**@}*/

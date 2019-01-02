/*
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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

typedef struct {
	wget_hpkp_db_t
		parent;
	char *
		fname;
	wget_hashmap_t *
		entries;
	wget_thread_mutex_t
		mutex;
	int64_t
		load_time;
} _hpkp_db_impl_t;

struct _wget_hpkp_st {
	const char *
		host;
	int64_t
		expires;
	int64_t
		created;
	int64_t
		maxage;
	char
		include_subdomains;
	wget_vector_t *
		pins;
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
} wget_hpkp_pin_t;

/**
 * \file
 * \brief HTTP Public Key Pinning (RFC 7469) routines
 * \defgroup libwget-hpkp HTTP Public Key Pinning (RFC 7469) routines
 * @{
 *
 * This is an implementation of RFC 7469.
 */

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int G_GNUC_WGET_PURE _hash_hpkp(const wget_hpkp_t *hpkp)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)hpkp->host; *p; p++)
		hash = hash * 101 + *p; // possible integer overflow, suppression above

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

	if ((n = strcmp(p1->hash_type, p2->hash_type)))
		return n;

	if (p1->pinsize < p2->pinsize)
		return -1;

	if (p1->pinsize > p2->pinsize)
		return 1;

	return memcmp(p1->pin, p2->pin, p1->pinsize);
}

static void _hpkp_pin_free(wget_hpkp_pin_t *pin)
{
	if (pin) {
		xfree(pin->hash_type);
		xfree(pin->pin);
		xfree(pin->pin_b64);
	}
}

/**
 * \param[in] hpkp An HPKP database entry
 * \param[in] pin_type The type of hash supplied, e.g. "sha256"
 * \param[in] pin_b64 The public key hash in base64 format
 *
 * Adds a public key hash to HPKP database entry.
 */
void wget_hpkp_pin_add(wget_hpkp_t *hpkp, const char *pin_type, const char *pin_b64)
{
	wget_hpkp_pin_t *pin = xcalloc(1, sizeof(wget_hpkp_pin_t));
	size_t len_b64 = strlen(pin_b64);

	pin->hash_type = wget_strdup(pin_type);
	pin->pin_b64 = wget_strdup(pin_b64);
	pin->pin = (unsigned char *)wget_base64_decode_alloc(pin_b64, len_b64, &pin->pinsize);

	if (!hpkp->pins) {
		hpkp->pins = wget_vector_create(5, (wget_vector_compare_t)_compare_pin);
		wget_vector_set_destructor(hpkp->pins, (wget_vector_destructor_t)_hpkp_pin_free);
	}

	wget_vector_add_noalloc(hpkp->pins, pin);
}

/**
 * \param[in] hpkp An HPKP database entry
 *
 * Free hpkp_t instance created by wget_hpkp_new()
 * It can be used as destructor function in vectors and hashmaps.
 * If `hpkp` is NULL this function does nothing.
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

/**
 * \param[in] hpkp An HPKP database entry
 * \param[in] host Hostname of the web server
 *
 * Sets the hostname of the web server into given HPKP database entry.
 */
void wget_hpkp_set_host(wget_hpkp_t *hpkp, const char *host)
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
void wget_hpkp_set_maxage(wget_hpkp_t *hpkp, time_t maxage)
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
void wget_hpkp_set_include_subdomains(wget_hpkp_t *hpkp, int include_subdomains)
{
	hpkp->include_subdomains = !!include_subdomains;
}

/**
 * \param[in] hpkp An HPKP database entry
 * \return The number of public key hashes added.
 *
 * Gets the number of public key hashes added to the given HPKP database entry.
 */
size_t wget_hpkp_get_n_pins(wget_hpkp_t *hpkp)
{
	return (size_t) wget_vector_size(hpkp->pins);
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
void wget_hpkp_get_pins_b64(wget_hpkp_t *hpkp, const char **pin_types, const char **pins_b64)
{
	int i, n_pins;

	n_pins = wget_vector_size(hpkp->pins);

	for (i = 0; i < n_pins; i++) {
		wget_hpkp_pin_t *pin = (wget_hpkp_pin_t *) wget_vector_get(hpkp->pins, i);
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
void wget_hpkp_get_pins(wget_hpkp_t *hpkp, const char **pin_types, size_t *sizes, const void **pins)
{
	int i, n_pins;

	n_pins = wget_vector_size(hpkp->pins);

	for (i = 0; i < n_pins; i++) {
		wget_hpkp_pin_t *pin = (wget_hpkp_pin_t *) wget_vector_get(hpkp->pins, i);
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
const char * wget_hpkp_get_host(wget_hpkp_t *hpkp)
{
	return hpkp->host;
}

/**
 * \param[in] hpkp An HPKP database entry
 * \return The maximum time (in seconds) the entry is valid
 *
 * Gets the maximum time this entry is valid for, as set by \ref wget_hpkp_set_maxage "wget_hpkp_set_maxage()"
 */
time_t wget_hpkp_get_maxage(wget_hpkp_t *hpkp)
{
	return hpkp->maxage;
}

/**
 * \param[in] hpkp An HPKP database entry
 * \return 1 if the HPKP entry is also valid for all subdomains, 0 otherwise
 *
 * Gets whether the HPKP database entry is also valid for the subdomains.
 */
int wget_hpkp_get_include_subdomains(wget_hpkp_t *hpkp)
{
	return hpkp->include_subdomains;
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
void wget_hpkp_db_deinit(wget_hpkp_db_t *hpkp_db)
{
	_hpkp_db_impl_t *hpkp_db_priv = (_hpkp_db_impl_t *) hpkp_db;

	if (hpkp_db_priv) {
		xfree(hpkp_db_priv->fname);
		wget_thread_mutex_lock(hpkp_db_priv->mutex);
		wget_hashmap_free(&hpkp_db_priv->entries);
		wget_thread_mutex_unlock(hpkp_db_priv->mutex);

		wget_thread_mutex_destroy(&hpkp_db_priv->mutex);
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
void wget_hpkp_db_free(wget_hpkp_db_t **hpkp_db)
{
	if (hpkp_db && *hpkp_db) {
		(*(*hpkp_db)->vtable->free)(*hpkp_db);
		*hpkp_db = NULL;
	}
}
static void impl_hpkp_db_free(wget_hpkp_db_t *hpkp_db)
{
	_hpkp_db_impl_t *hpkp_db_priv = (_hpkp_db_impl_t *) hpkp_db;

	wget_hpkp_db_deinit(hpkp_db);
	xfree(hpkp_db_priv);
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
int wget_hpkp_db_check_pubkey(wget_hpkp_db_t *hpkp_db, const char *host, const void *pubkey, size_t pubkeysize)
{
	return (*hpkp_db->vtable->check_pubkey)(hpkp_db, host, pubkey, pubkeysize);
}
static int impl_hpkp_db_check_pubkey(wget_hpkp_db_t *hpkp_db, const char *host, const void *pubkey, size_t pubkeysize)
{
	_hpkp_db_impl_t *hpkp_db_priv = (_hpkp_db_impl_t *) hpkp_db;

	wget_hpkp_t key;
	wget_hpkp_t *hpkp = NULL;
	char digest[wget_hash_get_len(WGET_DIGTYPE_SHA256)];
	int subdomain = 0;

	for (const char *domain = host; *domain && !hpkp; domain = strchrnul(domain, '.')) {
		while (*domain == '.')
			domain++;

		key.host = domain;

		if (!wget_hashmap_get(hpkp_db_priv->entries, &key, &hpkp))
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
void wget_hpkp_db_add(wget_hpkp_db_t *hpkp_db, wget_hpkp_t **hpkp)
{
	(*hpkp_db->vtable->add)(hpkp_db, *hpkp);
	*hpkp = NULL;
}
static void impl_hpkp_db_add(wget_hpkp_db_t *hpkp_db, wget_hpkp_t *hpkp)
{
	_hpkp_db_impl_t *hpkp_db_priv = (_hpkp_db_impl_t *) hpkp_db;

	if (!hpkp)
		return;

	wget_thread_mutex_lock(hpkp_db_priv->mutex);

	if (hpkp->maxage == 0 || wget_vector_size(hpkp->pins) == 0) {
		if (wget_hashmap_remove(hpkp_db_priv->entries, hpkp))
			debug_printf("removed HPKP %s\n", hpkp->host);
		wget_hpkp_free(hpkp);
	} else {
		wget_hpkp_t *old;

		if (wget_hashmap_get(hpkp_db_priv->entries, hpkp, &old)) {
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
			wget_hashmap_put_noalloc(hpkp_db_priv->entries, hpkp, hpkp);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(hpkp_db_priv->mutex);
}

static int _hpkp_db_load(_hpkp_db_impl_t *hpkp_db_priv, FILE *fp)
{
	int64_t created, max_age;
	long long _created, _max_age;
	int include_subdomains;

	wget_hpkp_t *hpkp = NULL;
	struct stat st;
	char *buf = NULL;
	size_t bufsize = 0;
	ssize_t buflen;
	char hash_type[32], host[256], pin_b64[256];
	int64_t now = time(NULL);

	// if the database file hasn't changed since the last read
	// there's no need to reload

	if (fstat(fileno(fp), &st) == 0) {
		if (st.st_mtime != hpkp_db_priv->load_time)
			hpkp_db_priv->load_time = st.st_mtime;
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
			wget_hpkp_db_add((wget_hpkp_db_t *) hpkp_db_priv, &hpkp);

			if (sscanf(linep, "%255s %d %lld %lld", host, &include_subdomains, &_created, &_max_age) == 4) {
				created = _created;
				max_age = _max_age;
				if (created < 0 || max_age < 0 || created >= INT64_MAX / 2 || max_age >= INT64_MAX / 2) {
					max_age = 0; // avoid integer overflow here
				}
				int64_t expires = created + max_age;
				if (max_age && expires >= now) {
					hpkp = wget_hpkp_new();
					hpkp->host = wget_strdup(host);
					hpkp->maxage = max_age;
					hpkp->created = created;
					hpkp->expires = expires;
					hpkp->include_subdomains = !!include_subdomains;
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

	wget_hpkp_db_add((wget_hpkp_db_t *) hpkp_db_priv, &hpkp);

	xfree(buf);

	if (ferror(fp)) {
		hpkp_db_priv->load_time = 0; // reload on next call to this function
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
int wget_hpkp_db_load(wget_hpkp_db_t *hpkp_db)
{
	if (! hpkp_db)
		return 0;
	return (*hpkp_db->vtable->load)(hpkp_db);
}
static int impl_hpkp_db_load(wget_hpkp_db_t *hpkp_db)
{
	_hpkp_db_impl_t *hpkp_db_priv = (_hpkp_db_impl_t *) hpkp_db;

	if (!hpkp_db_priv->fname || !*hpkp_db_priv->fname)
		return 0;

	if (wget_update_file(hpkp_db_priv->fname, (wget_update_load_t) _hpkp_db_load, NULL, hpkp_db_priv)) {
		error_printf(_("Failed to read HPKP data\n"));
		return -1;
	} else {
		debug_printf("Fetched HPKP data from '%s'\n", hpkp_db_priv->fname);
		return 0;
	}
}

static int _hpkp_save_pin(FILE *fp, wget_hpkp_pin_t *pin)
{
	wget_fprintf(fp, "*%s %s\n", pin->hash_type, pin->pin_b64);

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
		wget_fprintf(fp, "%s %d %lld %lld\n", hpkp->host, hpkp->include_subdomains, (long long)hpkp->created, (long long)hpkp->maxage);

		if (ferror(fp))
			return -1;

		return wget_vector_browse(hpkp->pins, (wget_vector_browse_t)_hpkp_save_pin, fp);
	}

	return 0;
}

static int _hpkp_db_save(_hpkp_db_impl_t *hpkp_db_priv, FILE *fp)
{
	wget_hashmap_t *entries = hpkp_db_priv->entries;

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
int wget_hpkp_db_save(wget_hpkp_db_t *hpkp_db)
{
	if (! hpkp_db)
		return -1;

	return (*hpkp_db->vtable->save)(hpkp_db);
}
static int impl_hpkp_db_save(wget_hpkp_db_t *hpkp_db)
{
	_hpkp_db_impl_t *hpkp_db_priv = (_hpkp_db_impl_t *) hpkp_db;

	int size;

	if (!hpkp_db_priv->fname || !*hpkp_db_priv->fname)
		return -1;

	if (wget_update_file(hpkp_db_priv->fname,
			     (wget_update_load_t) _hpkp_db_load,
			     (wget_update_load_t) _hpkp_db_save,
			     hpkp_db_priv)) {
		error_printf(_("Failed to write HPKP file '%s'\n"), hpkp_db_priv->fname);
		return -1;
	}

	if ((size = wget_hashmap_size(hpkp_db_priv->entries)))
		debug_printf("Saved %d HPKP entr%s into '%s'\n", size, size != 1 ? "ies" : "y", hpkp_db_priv->fname);
	else
		debug_printf("No HPKP entries to save. Table is empty.\n");

	return 0;
}

static struct wget_hpkp_db_vtable vtable = {
	.load = impl_hpkp_db_load,
	.save = impl_hpkp_db_save,
	.free = impl_hpkp_db_free,
	.add = impl_hpkp_db_add,
	.check_pubkey = impl_hpkp_db_check_pubkey
};

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
wget_hpkp_db_t *wget_hpkp_db_init(wget_hpkp_db_t *hpkp_db, const char *fname)
{
	_hpkp_db_impl_t *hpkp_db_priv = (_hpkp_db_impl_t *) hpkp_db;

	if (!hpkp_db_priv)
		hpkp_db_priv = xcalloc(1, sizeof(_hpkp_db_impl_t));
	else
		memset(hpkp_db_priv, 0, sizeof(*hpkp_db_priv));

	hpkp_db_priv->parent.vtable = &vtable;
	if (fname)
		hpkp_db_priv->fname = wget_strdup(fname);
	hpkp_db_priv->entries = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_hpkp, (wget_hashmap_compare_t)_compare_hpkp);
	wget_hashmap_set_key_destructor(hpkp_db_priv->entries, (wget_hashmap_key_destructor_t)wget_hpkp_free);

	/*
	 * Keys and values for the hashmap are 'hpkp' entries, so value == key.
	 * The hash function hashes hostname.
	 * The compare function compares hostname.
	 *
	 * Since the value == key, we just need the value destructor for freeing hashmap entries.
	 */

	wget_thread_mutex_init(&hpkp_db_priv->mutex);

	return (wget_hpkp_db_t *) hpkp_db_priv;
}

/**
 * \param[in] hpkp_db HPKP database created using wget_hpkp_db_init()
 * \param[in] fname Name of the file where the data should be stored, or NULL
 *
 * Changes the file where data should be stored. Works only for databases created by wget_hpkp_db_init().
 * This function does no file IO, data is loaded when wget_hpkp_db_load() is called.
 */
void wget_hpkp_db_set_fname(wget_hpkp_db_t *hpkp_db, const char *fname)
{
	_hpkp_db_impl_t *hpkp_db_priv = (_hpkp_db_impl_t *) hpkp_db;

	xfree(hpkp_db_priv->fname);
	if (fname)
		hpkp_db_priv->fname = wget_strdup(fname);
}

/**@}*/

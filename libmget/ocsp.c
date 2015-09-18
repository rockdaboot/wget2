/*
 * Copyright(c) 2014 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * OCSP caching routines
 *
 * Changelog
 * 08.01.2015  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include <libmget.h>
#include "private.h"

struct _mget_ocsp_db_st {
	mget_hashmap_t *
		fingerprints;
	mget_hashmap_t *
		hosts;
	mget_thread_mutex_t
		mutex;
};

struct _mget_ocsp_st {
	const char *
		key;
	time_t
		maxage; // expiry time
	time_t
		mtime; // creation time
	int
		valid; // 1=valid, 0=revoked
};

static unsigned int G_GNUC_MGET_PURE _hash_ocsp(const mget_ocsp_t *ocsp)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)ocsp->key; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static int G_GNUC_MGET_NONNULL_ALL _compare_ocsp(const mget_ocsp_t *h1, const mget_ocsp_t *h2)
{
	return strcmp(h1->key, h2->key);
}

mget_ocsp_t *mget_ocsp_init(mget_ocsp_t *ocsp)
{
	if (!ocsp)
		ocsp = xmalloc(sizeof(mget_ocsp_t));

	memset(ocsp, 0, sizeof(*ocsp));
	ocsp->mtime = time(NULL);

	return ocsp;
}

void mget_ocsp_deinit(mget_ocsp_t *ocsp)
{
	if (ocsp) {
		xfree(ocsp->key);
	}
}

void mget_ocsp_free(mget_ocsp_t *ocsp)
{
	if (ocsp) {
		mget_ocsp_deinit(ocsp);
		xfree(ocsp);
	}
}

mget_ocsp_t *mget_ocsp_new(const char *fingerprint, time_t maxage, int valid)
{
	mget_ocsp_t *ocsp = mget_ocsp_init(NULL);

	ocsp->key = mget_strdup(fingerprint);
	ocsp->maxage = maxage;
	ocsp->valid = valid;

	return ocsp;
}

int mget_ocsp_fingerprint_in_cache(const mget_ocsp_db_t *ocsp_db, const char *fingerprint, int *revoked)
{
	if (ocsp_db) {
		mget_ocsp_t ocsp, *ocspp;

		// look for an exact match
		ocsp.key = fingerprint;
		if ((ocspp = mget_hashmap_get(ocsp_db->fingerprints, &ocsp)) && ocspp->maxage >= time(NULL)) {
			if (revoked)
				*revoked = !ocspp->valid;
			return 1;
		}
	}

	return 0;
}

int mget_ocsp_hostname_is_valid(const mget_ocsp_db_t *ocsp_db, const char *hostname)
{
	if (ocsp_db) {
		mget_ocsp_t ocsp, *ocspp;

		// look for an exact match
		ocsp.key = hostname;
		if ((ocspp = mget_hashmap_get(ocsp_db->hosts, &ocsp)) && ocspp->maxage >= time(NULL)) {
			return 1;
		}
	}

	return 0;
}

mget_ocsp_db_t *mget_ocsp_db_init(mget_ocsp_db_t *ocsp_db)
{
	if (!ocsp_db)
		ocsp_db = xmalloc(sizeof(mget_ocsp_db_t));

	memset(ocsp_db, 0, sizeof(*ocsp_db));

	ocsp_db->fingerprints = mget_hashmap_create(16, -2, (unsigned int(*)(const void *))_hash_ocsp, (int(*)(const void *, const void *))_compare_ocsp);
	mget_hashmap_set_key_destructor(ocsp_db->fingerprints, (void(*)(void *))mget_ocsp_free);
	mget_hashmap_set_value_destructor(ocsp_db->fingerprints, (void(*)(void *))mget_ocsp_free);

	ocsp_db->hosts = mget_hashmap_create(16, -2, (unsigned int(*)(const void *))_hash_ocsp, (int(*)(const void *, const void *))_compare_ocsp);
	mget_hashmap_set_key_destructor(ocsp_db->hosts, (void(*)(void *))mget_ocsp_free);
	mget_hashmap_set_value_destructor(ocsp_db->hosts, (void(*)(void *))mget_ocsp_free);

	mget_thread_mutex_init(&ocsp_db->mutex);

	return ocsp_db;
}

void mget_ocsp_db_deinit(mget_ocsp_db_t *ocsp_db)
{
	if (ocsp_db) {
		mget_thread_mutex_lock(&ocsp_db->mutex);
		mget_hashmap_free(&ocsp_db->fingerprints);
		mget_hashmap_free(&ocsp_db->hosts);
		mget_thread_mutex_unlock(&ocsp_db->mutex);
	}
}

void mget_ocsp_db_free(mget_ocsp_db_t **ocsp_db)
{
	if (ocsp_db) {
		mget_ocsp_db_deinit(*ocsp_db);
		xfree(*ocsp_db);
	}
}

void mget_ocsp_db_add_fingerprint(mget_ocsp_db_t *ocsp_db, mget_ocsp_t *ocsp)
{
	if (!ocsp)
		return;

	if (!ocsp_db) {
		mget_ocsp_free(ocsp);
		return;
	}

	mget_thread_mutex_lock(&ocsp_db->mutex);

	if (ocsp->maxage == 0) {
		if (mget_hashmap_remove(ocsp_db->fingerprints, ocsp))
			debug_printf("removed OCSP cert %s\n", ocsp->key);
		mget_ocsp_free(ocsp);
	} else {
		mget_ocsp_t *old = mget_hashmap_get(ocsp_db->fingerprints, ocsp);

		if (old) {
			if (old->mtime < ocsp->mtime) {
				old->mtime = ocsp->mtime;
				old->maxage = ocsp->maxage;
				old->valid = ocsp->valid;
				debug_printf("update OCSP cert %s (maxage=%ld,valid=%d)\n", old->key, old->maxage, old->valid);
			}
			mget_ocsp_free(ocsp);
		} else {
			// key and value are the same to make mget_hashmap_get() return old 'ocsp'
			debug_printf("add OCSP cert %s (maxage=%ld,valid=%d)\n", ocsp->key, ocsp->maxage, ocsp->valid);
			mget_hashmap_put_noalloc(ocsp_db->fingerprints, ocsp, ocsp);
			// no need to free anything here
		}
	}

	mget_thread_mutex_unlock(&ocsp_db->mutex);
}

void mget_ocsp_db_add_host(mget_ocsp_db_t *ocsp_db, mget_ocsp_t *ocsp)
{
	if (!ocsp)
		return;

	if (!ocsp_db) {
		mget_ocsp_free(ocsp);
		return;
	}

	mget_thread_mutex_lock(&ocsp_db->mutex);

	if (ocsp->maxage == 0) {
		if (mget_hashmap_remove(ocsp_db->hosts, ocsp))
			debug_printf("removed OCSP host %s\n", ocsp->key);
		mget_ocsp_free(ocsp);
	} else {
		mget_ocsp_t *old = mget_hashmap_get(ocsp_db->hosts, ocsp);

		if (old) {
			if (old->mtime < ocsp->mtime) {
				old->mtime = ocsp->mtime;
				old->maxage = ocsp->maxage;
				old->valid = ocsp->valid;
				debug_printf("update OCSP host %s (maxage=%ld)\n", old->key, old->maxage);
			}
			mget_ocsp_free(ocsp);
		} else {
			// key and value are the same to make mget_hashmap_get() return old 'ocsp'
			mget_hashmap_put_noalloc(ocsp_db->hosts, ocsp, ocsp);
			debug_printf("add OCSP host %s (maxage=%ld)\n", ocsp->key, ocsp->maxage);
			// no need to free anything here
		}
	}

	mget_thread_mutex_unlock(&ocsp_db->mutex);
}

// load the OCSP cache from a flat file
// not thread-save

static int _ocsp_db_load(mget_ocsp_db_t *ocsp_db, const char *fname, int load_hosts)
{
	mget_ocsp_t ocsp;
	FILE *fp;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	time_t now = time(NULL);
	int ok, nentries = 0;

	if ((fp = fopen(fname, "r"))) {
		while ((buflen = mget_getline(&buf, &bufsize, fp)) >= 0) {
			linep = buf;

			while (isspace(*linep)) linep++; // ignore leading whitespace
			if (!*linep) continue; // skip empty lines

			if (*linep == '#')
				continue; // skip comments

			// strip off \r\n
			while (buflen > 0 && (buf[buflen] == '\n' || buf[buflen] == '\r'))
				buf[--buflen] = 0;

			mget_ocsp_init(&ocsp);
			ok = 0;

			// parse cert's sha-256 checksum
			if (*linep) {
				for (p = linep; *linep && !isspace(*linep);) linep++;
				ocsp.key = strndup(p, linep - p);
			}

			// parse max age
			if (*linep) {
				for (p = ++linep; *linep && !isspace(*linep);) linep++;
				ocsp.maxage = atol(p);
				if (ocsp.maxage < now) {
					// drop expired entry
					mget_ocsp_deinit(&ocsp);
					continue;
				}
				ok = 1;
			}

			// parse mtime (age of this entry)
			if (*linep) {
				for (p = ++linep; *linep && !isspace(*linep);) linep++;
				ocsp.mtime = atol(p);
			}

			// parse mtime (age of this entry)
			if (*linep) {
				for (p = ++linep; *linep && !isspace(*linep);) linep++;
				ocsp.valid = atoi(p);
			}

			if (ok) {
				if (load_hosts)
					mget_ocsp_db_add_host(ocsp_db, mget_memdup(&ocsp, sizeof(ocsp)));
				else
					mget_ocsp_db_add_fingerprint(ocsp_db, mget_memdup(&ocsp, sizeof(ocsp)));
			} else {
				mget_ocsp_deinit(&ocsp);
				error_printf(_("Failed to parse OCSP line: '%s'\n"), buf);
			}
		}

		xfree(buf);
		fclose(fp);

		nentries = mget_hashmap_size(load_hosts ? ocsp_db->hosts : ocsp_db->fingerprints);

		debug_printf(_("have %d OCSP %s%s in cache\n"), nentries, load_hosts ? "host" : "fingerprint", nentries !=1 ? "s" : "");
	} else if (errno != ENOENT)
		error_printf(_("Failed to open OCSP file '%s' (%d)\n"), fname, errno);

	return nentries;
}

int mget_ocsp_db_load(mget_ocsp_db_t *ocsp_db, const char *fname)
{
	if (!ocsp_db || !fname || !*fname)
		return -1;

	char fname_hosts[strlen(fname) + 6 + 1];
	snprintf(fname_hosts, sizeof(fname_hosts), "%s_hosts", fname);

	return _ocsp_db_load(ocsp_db, fname, 0) + _ocsp_db_load(ocsp_db, fname_hosts, 1);
}

static int G_GNUC_MGET_NONNULL_ALL _ocsp_save_entry(FILE *fp, const mget_ocsp_t *ocsp)
{
	fprintf(fp, "%s %ld %ld %d\n", ocsp->key, ocsp->maxage, ocsp->mtime, ocsp->valid);
	return 0;
}

static int G_GNUC_MGET_NONNULL_ALL _ocsp_save_host(FILE *fp, const mget_ocsp_t *ocsp)
{
	fprintf(fp, "%s %ld %ld\n", ocsp->key, ocsp->maxage, ocsp->mtime);
	return 0;
}

// save the OCSP cache to a flat file
// not thread-save

static int _ocsp_db_save(mget_hashmap_t *map, const char *fname, int save_hosts)
{
	FILE *fp;
	int ret = -1, size;

	if ((size = mget_hashmap_size(map)) <= 0)
		return -1;

	if ((fp = fopen(fname, "w"))) {
		fputs("#OCSP 1.0 file\n", fp);
		fputs("#Generated by Mget " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		if (save_hosts) {
			fputs("<hostname> <time_t maxage> <time_t mtime>\n\n", fp);
			mget_hashmap_browse(map, (int(*)(void *, const void *, void *))_ocsp_save_host, fp);
		} else {
			fputs("<sha256 fingerprint of cert> <time_t maxage> <time_t mtime> <valid>\n\n", fp);
			mget_hashmap_browse(map, (int(*)(void *, const void *, void *))_ocsp_save_entry, fp);
		}

		if (!ferror(fp))
			ret = 0;

		if (fclose(fp))
			ret = -1;

		if (ret)
			error_printf(_("Failed to write to OCSP file '%s' (%d)\n"), fname, errno);
		else
			debug_printf(_("saved %d OCSP entr%s into '%s'\n"), size, size != 1 ? "ies" : "y", fname);
	} else
		error_printf(_("Failed to open OCSP file '%s' (%d)\n"), fname, errno);

	return ret;
}

int mget_ocsp_db_save(mget_ocsp_db_t *ocsp_db, const char *fname)
{
	if (!ocsp_db || !fname || !*fname)
		return -1;

	int nentries;
	char fname_hosts[strlen(fname) + 6 + 1];
	snprintf(fname_hosts, sizeof(fname_hosts), "%s_hosts", fname);

	_ocsp_db_load(ocsp_db, fname, 0);
	nentries = _ocsp_db_save(ocsp_db->fingerprints, fname, 0);

	_ocsp_db_load(ocsp_db, fname_hosts, 1);
	return nentries + _ocsp_db_save(ocsp_db->hosts, fname_hosts, 1);
}

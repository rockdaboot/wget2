/*
 * Copyright(c) 2014 Tim Ruehsen
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

#include <libwget.h>
#include "private.h"

struct _wget_ocsp_db_st {
	wget_hashmap_t *
		fingerprints;
	wget_hashmap_t *
		hosts;
	wget_thread_mutex_t
		mutex;
};

struct _wget_ocsp_st {
	const char *
		key;
	time_t
		maxage; // expiry time
	time_t
		mtime; // creation time
	int
		valid; // 1=valid, 0=revoked
};

static unsigned int G_GNUC_WGET_PURE _hash_ocsp(const wget_ocsp_t *ocsp)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)ocsp->key; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static int G_GNUC_WGET_NONNULL_ALL _compare_ocsp(const wget_ocsp_t *h1, const wget_ocsp_t *h2)
{
	return strcmp(h1->key, h2->key);
}

wget_ocsp_t *wget_ocsp_init(wget_ocsp_t *ocsp)
{
	if (!ocsp)
		ocsp = xmalloc(sizeof(wget_ocsp_t));

	memset(ocsp, 0, sizeof(*ocsp));
	ocsp->mtime = time(NULL);

	return ocsp;
}

void wget_ocsp_deinit(wget_ocsp_t *ocsp)
{
	if (ocsp) {
		xfree(ocsp->key);
	}
}

void wget_ocsp_free(wget_ocsp_t *ocsp)
{
	if (ocsp) {
		wget_ocsp_deinit(ocsp);
		xfree(ocsp);
	}
}

wget_ocsp_t *wget_ocsp_new(const char *fingerprint, time_t maxage, int valid)
{
	wget_ocsp_t *ocsp = wget_ocsp_init(NULL);

	ocsp->key = wget_strdup(fingerprint);
	ocsp->maxage = maxage;
	ocsp->valid = valid;

	return ocsp;
}

int wget_ocsp_fingerprint_in_cache(const wget_ocsp_db_t *ocsp_db, const char *fingerprint, int *revoked)
{
	if (ocsp_db) {
		wget_ocsp_t ocsp, *ocspp;

		// look for an exact match
		ocsp.key = fingerprint;
		if ((ocspp = wget_hashmap_get(ocsp_db->fingerprints, &ocsp)) && ocspp->maxage >= time(NULL)) {
			if (revoked)
				*revoked = !ocspp->valid;
			return 1;
		}
	}

	return 0;
}

int wget_ocsp_hostname_is_valid(const wget_ocsp_db_t *ocsp_db, const char *hostname)
{
	if (ocsp_db) {
		wget_ocsp_t ocsp, *ocspp;

		// look for an exact match
		ocsp.key = hostname;
		if ((ocspp = wget_hashmap_get(ocsp_db->hosts, &ocsp)) && ocspp->maxage >= time(NULL)) {
			return 1;
		}
	}

	return 0;
}

wget_ocsp_db_t *wget_ocsp_db_init(wget_ocsp_db_t *ocsp_db)
{
	if (!ocsp_db)
		ocsp_db = xmalloc(sizeof(wget_ocsp_db_t));

	memset(ocsp_db, 0, sizeof(*ocsp_db));

	ocsp_db->fingerprints = wget_hashmap_create(16, -2, (unsigned int(*)(const void *))_hash_ocsp, (int(*)(const void *, const void *))_compare_ocsp);
	wget_hashmap_set_key_destructor(ocsp_db->fingerprints, (void(*)(void *))wget_ocsp_free);
	wget_hashmap_set_value_destructor(ocsp_db->fingerprints, (void(*)(void *))wget_ocsp_free);

	ocsp_db->hosts = wget_hashmap_create(16, -2, (unsigned int(*)(const void *))_hash_ocsp, (int(*)(const void *, const void *))_compare_ocsp);
	wget_hashmap_set_key_destructor(ocsp_db->hosts, (void(*)(void *))wget_ocsp_free);
	wget_hashmap_set_value_destructor(ocsp_db->hosts, (void(*)(void *))wget_ocsp_free);

	wget_thread_mutex_init(&ocsp_db->mutex);

	return ocsp_db;
}

void wget_ocsp_db_deinit(wget_ocsp_db_t *ocsp_db)
{
	if (ocsp_db) {
		wget_thread_mutex_lock(&ocsp_db->mutex);
		wget_hashmap_free(&ocsp_db->fingerprints);
		wget_hashmap_free(&ocsp_db->hosts);
		wget_thread_mutex_unlock(&ocsp_db->mutex);
	}
}

void wget_ocsp_db_free(wget_ocsp_db_t **ocsp_db)
{
	if (ocsp_db) {
		wget_ocsp_db_deinit(*ocsp_db);
		xfree(*ocsp_db);
	}
}

void wget_ocsp_db_add_fingerprint(wget_ocsp_db_t *ocsp_db, wget_ocsp_t *ocsp)
{
	if (!ocsp)
		return;

	if (!ocsp_db) {
		wget_ocsp_free(ocsp);
		return;
	}

	wget_thread_mutex_lock(&ocsp_db->mutex);

	if (ocsp->maxage == 0) {
		if (wget_hashmap_remove(ocsp_db->fingerprints, ocsp))
			debug_printf("removed OCSP cert %s\n", ocsp->key);
		wget_ocsp_free(ocsp);
	} else {
		wget_ocsp_t *old = wget_hashmap_get(ocsp_db->fingerprints, ocsp);

		if (old) {
			if (old->mtime < ocsp->mtime) {
				old->mtime = ocsp->mtime;
				old->maxage = ocsp->maxage;
				old->valid = ocsp->valid;
				debug_printf("update OCSP cert %s (maxage=%ld,valid=%d)\n", old->key, old->maxage, old->valid);
			}
			wget_ocsp_free(ocsp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'ocsp'
			debug_printf("add OCSP cert %s (maxage=%ld,valid=%d)\n", ocsp->key, ocsp->maxage, ocsp->valid);
			wget_hashmap_put_noalloc(ocsp_db->fingerprints, ocsp, ocsp);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(&ocsp_db->mutex);
}

void wget_ocsp_db_add_host(wget_ocsp_db_t *ocsp_db, wget_ocsp_t *ocsp)
{
	if (!ocsp)
		return;

	if (!ocsp_db) {
		wget_ocsp_free(ocsp);
		return;
	}

	wget_thread_mutex_lock(&ocsp_db->mutex);

	if (ocsp->maxage == 0) {
		if (wget_hashmap_remove(ocsp_db->hosts, ocsp))
			debug_printf("removed OCSP host %s\n", ocsp->key);
		wget_ocsp_free(ocsp);
	} else {
		wget_ocsp_t *old = wget_hashmap_get(ocsp_db->hosts, ocsp);

		if (old) {
			if (old->mtime < ocsp->mtime) {
				old->mtime = ocsp->mtime;
				old->maxage = ocsp->maxage;
				old->valid = ocsp->valid;
				debug_printf("update OCSP host %s (maxage=%ld)\n", old->key, old->maxage);
			}
			wget_ocsp_free(ocsp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'ocsp'
			wget_hashmap_put_noalloc(ocsp_db->hosts, ocsp, ocsp);
			debug_printf("add OCSP host %s (maxage=%ld)\n", ocsp->key, ocsp->maxage);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(&ocsp_db->mutex);
}

// load the OCSP cache from a flat file
// not thread-save

static int _ocsp_db_load(wget_ocsp_db_t *ocsp_db, const char *fname, int load_hosts)
{
	wget_ocsp_t ocsp;
	FILE *fp;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	time_t now = time(NULL);
	int ok, nentries = 0;

	if ((fp = fopen(fname, "r"))) {
		while ((buflen = wget_getline(&buf, &bufsize, fp)) >= 0) {
			linep = buf;

			while (isspace(*linep)) linep++; // ignore leading whitespace
			if (!*linep) continue; // skip empty lines

			if (*linep == '#')
				continue; // skip comments

			// strip off \r\n
			while (buflen > 0 && (buf[buflen] == '\n' || buf[buflen] == '\r'))
				buf[--buflen] = 0;

			wget_ocsp_init(&ocsp);
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
					wget_ocsp_deinit(&ocsp);
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
					wget_ocsp_db_add_host(ocsp_db, wget_memdup(&ocsp, sizeof(ocsp)));
				else
					wget_ocsp_db_add_fingerprint(ocsp_db, wget_memdup(&ocsp, sizeof(ocsp)));
			} else {
				wget_ocsp_deinit(&ocsp);
				error_printf(_("Failed to parse OCSP line: '%s'\n"), buf);
			}
		}

		xfree(buf);
		fclose(fp);

		nentries = wget_hashmap_size(load_hosts ? ocsp_db->hosts : ocsp_db->fingerprints);

		debug_printf(_("have %d OCSP %s%s in cache\n"), nentries, load_hosts ? "host" : "fingerprint", nentries !=1 ? "s" : "");
	} else if (errno != ENOENT)
		error_printf(_("Failed to open OCSP file '%s' (%d)\n"), fname, errno);

	return nentries;
}

int wget_ocsp_db_load(wget_ocsp_db_t *ocsp_db, const char *fname)
{
	if (!ocsp_db || !fname || !*fname)
		return -1;

	char fname_hosts[strlen(fname) + 6 + 1];
	snprintf(fname_hosts, sizeof(fname_hosts), "%s_hosts", fname);

	return _ocsp_db_load(ocsp_db, fname, 0) + _ocsp_db_load(ocsp_db, fname_hosts, 1);
}

static int G_GNUC_WGET_NONNULL_ALL _ocsp_save_entry(FILE *fp, const wget_ocsp_t *ocsp)
{
	fprintf(fp, "%s %ld %ld %d\n", ocsp->key, ocsp->maxage, ocsp->mtime, ocsp->valid);
	return 0;
}

static int G_GNUC_WGET_NONNULL_ALL _ocsp_save_host(FILE *fp, const wget_ocsp_t *ocsp)
{
	fprintf(fp, "%s %ld %ld\n", ocsp->key, ocsp->maxage, ocsp->mtime);
	return 0;
}

// save the OCSP cache to a flat file
// not thread-save

static int _ocsp_db_save(wget_hashmap_t *map, const char *fname, int save_hosts)
{
	FILE *fp;
	int ret = -1, size;

	if ((size = wget_hashmap_size(map)) <= 0)
		return -1;

	if ((fp = fopen(fname, "w"))) {
		fputs("#OCSP 1.0 file\n", fp);
		fputs("#Generated by Wget " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		if (save_hosts) {
			fputs("<hostname> <time_t maxage> <time_t mtime>\n\n", fp);
			wget_hashmap_browse(map, (int(*)(void *, const void *, void *))_ocsp_save_host, fp);
		} else {
			fputs("<sha256 fingerprint of cert> <time_t maxage> <time_t mtime> <valid>\n\n", fp);
			wget_hashmap_browse(map, (int(*)(void *, const void *, void *))_ocsp_save_entry, fp);
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

int wget_ocsp_db_save(wget_ocsp_db_t *ocsp_db, const char *fname)
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

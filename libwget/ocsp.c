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
	unsigned char
		valid : 1; // 1=valid, 0=revoked
};

static unsigned int G_GNUC_WGET_PURE _hash_ocsp(const wget_ocsp_t *ocsp)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)ocsp->key; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static int G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PURE _compare_ocsp(const wget_ocsp_t *h1, const wget_ocsp_t *h2)
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
	ocsp->valid = !!valid;

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

	ocsp_db->fingerprints = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_ocsp, (wget_hashmap_compare_t)_compare_ocsp);
	wget_hashmap_set_key_destructor(ocsp_db->fingerprints, (wget_hashmap_key_destructor_t)wget_ocsp_free);
	wget_hashmap_set_value_destructor(ocsp_db->fingerprints, (wget_hashmap_value_destructor_t)wget_ocsp_free);

	ocsp_db->hosts = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_ocsp, (wget_hashmap_compare_t)_compare_ocsp);
	wget_hashmap_set_key_destructor(ocsp_db->hosts, (wget_hashmap_key_destructor_t)wget_ocsp_free);
	wget_hashmap_set_value_destructor(ocsp_db->hosts, (wget_hashmap_value_destructor_t)wget_ocsp_free);

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
				debug_printf("update OCSP cert %s (maxage=%lld,valid=%d)\n", old->key, (long long)old->maxage, old->valid);
			}
			wget_ocsp_free(ocsp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'ocsp'
			debug_printf("add OCSP cert %s (maxage=%lld,valid=%d)\n", ocsp->key, (long long)ocsp->maxage, ocsp->valid);
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
				debug_printf("update OCSP host %s (maxage=%lld)\n", old->key, (long long)old->maxage);
			}
			wget_ocsp_free(ocsp);
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'ocsp'
			wget_hashmap_put_noalloc(ocsp_db->hosts, ocsp, ocsp);
			debug_printf("add OCSP host %s (maxage=%lld)\n", ocsp->key, (long long)ocsp->maxage);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(&ocsp_db->mutex);
}

// load the OCSP cache from a flat file
// not thread-save

static int _ocsp_db_load(wget_ocsp_db_t *ocsp_db, FILE *fp, int load_hosts)
{
	wget_ocsp_t ocsp;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	time_t now = time(NULL);
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

		wget_ocsp_init(&ocsp);
		ok = 0;

		// parse cert's sha-256 checksum
		if (*linep) {
			for (p = linep; *linep && !isspace(*linep);) linep++;
			ocsp.key = wget_strmemdup(p, linep - p);
		}

		// parse max age
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep);) linep++;
			ocsp.maxage = (time_t)atoll(p);
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
			ocsp.mtime = (time_t)atoll(p);
		}

		// parse mtime (age of this entry)
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep);) linep++;
			ocsp.valid = !!atoi(p);
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

	if (ferror(fp))
		return -1;

	return 0;
}

static int _ocsp_db_load_hosts(void *ocsp_db, FILE *fp)
{
	return _ocsp_db_load(ocsp_db, fp, 1);
}

static int _ocsp_db_load_fingerprints(void *ocsp_db, FILE *fp)
{
	return _ocsp_db_load(ocsp_db, fp, 0);
}

int wget_ocsp_db_load(wget_ocsp_db_t *ocsp_db, const char *fname)
{
	int ret;

	if (!ocsp_db || !fname || !*fname)
		return -1;

	char fname_hosts[strlen(fname) + 6 + 1];
	snprintf(fname_hosts, sizeof(fname_hosts), "%s_hosts", fname);

	if ((ret = wget_update_file(fname_hosts, _ocsp_db_load_hosts, NULL, ocsp_db)))
		error_printf(_("Failed to read OCSP hosts\n"));
	else
		debug_printf(_("Fetched OCSP hosts from '%s'\n"), fname_hosts);

	if (wget_update_file(fname, _ocsp_db_load_fingerprints, NULL, ocsp_db)) {
		error_printf(_("Failed to read OCSP fingerprints\n"));
		ret = -1;
	} else
		debug_printf(_("Fetched OCSP fingerprints from '%s'\n"), fname);

	return ret;
}

static int G_GNUC_WGET_NONNULL_ALL _ocsp_save_fingerprint(FILE *fp, const wget_ocsp_t *ocsp)
{
	fprintf(fp, "%s %lld %lld %d\n", ocsp->key, (long long)ocsp->maxage, (long long)ocsp->mtime, ocsp->valid);
	return 0;
}

static int G_GNUC_WGET_NONNULL_ALL _ocsp_save_host(FILE *fp, const wget_ocsp_t *ocsp)
{
	fprintf(fp, "%s %lld %lld\n", ocsp->key, (long long)ocsp->maxage, (long long)ocsp->mtime);
	return 0;
}

static int _ocsp_db_save_hosts(void *ocsp_db, FILE *fp)
{
	wget_hashmap_t *map = ((wget_ocsp_db_t *)ocsp_db)->hosts;

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

static int _ocsp_db_save_fingerprints(void *ocsp_db, FILE *fp)
{
	wget_hashmap_t *map = ((wget_ocsp_db_t *)ocsp_db)->fingerprints;

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

// Save the OCSP hosts and fingerprints to flat files.
// Protected by flock()

int wget_ocsp_db_save(wget_ocsp_db_t *ocsp_db, const char *fname)
{
	int ret;

	if (!ocsp_db || !fname || !*fname)
		return -1;

	char fname_hosts[strlen(fname) + 6 + 1];
	snprintf(fname_hosts, sizeof(fname_hosts), "%s_hosts", fname);

	if ((ret = wget_update_file(fname_hosts, _ocsp_db_load_hosts, _ocsp_db_save_hosts, ocsp_db)))
		error_printf(_("Failed to write to OCSP hosts to '%s'\n"), fname_hosts);
	else
		debug_printf(_("Saved OCSP hosts to '%s'\n"), fname_hosts);

	if (wget_update_file(fname, _ocsp_db_load_fingerprints, _ocsp_db_save_fingerprints, ocsp_db)) {
		error_printf(_("Failed to write to OCSP fingerprints to '%s'\n"), fname);
		ret = -1;
	} else
		debug_printf(_("Saved OCSP fingerprints to '%s'\n"), fname);

	return ret;
}

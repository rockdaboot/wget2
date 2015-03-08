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
 * HSTS routines
 *
 * Changelog
 * 28.01.2014  Tim Ruehsen  created
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

struct _mget_hsts_db_st {
	mget_hashmap_t *
		entries;
	mget_thread_mutex_t
		mutex;
};

struct _mget_hsts_st {
	const char *
		host;
	time_t
		maxage; // expiry time
	time_t
		mtime; // creation time
	int
		port;
	unsigned int
		include_subdomains : 1; // whether or not subdomains are included
};

static unsigned int G_GNUC_MGET_PURE _hash_hsts(const mget_hsts_t *hsts)
{
	unsigned int hash = hsts->port;
	const unsigned char *p;

	for (p = (unsigned char *)hsts->host; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static int G_GNUC_MGET_NONNULL_ALL _compare_hsts(const mget_hsts_t *h1, const mget_hsts_t *h2)
{
	int n;

	if (!(n = strcmp(h1->host, h2->host)))
		return h1->port - h2->port;

	return n;
}

mget_hsts_t *mget_hsts_init(mget_hsts_t *hsts)
{
	if (!hsts)
		hsts = xmalloc(sizeof(mget_hsts_t));

	memset(hsts, 0, sizeof(*hsts));
	hsts->mtime = time(NULL);

	return hsts;
}

void mget_hsts_deinit(mget_hsts_t *hsts)
{
	if (hsts) {
		xfree(hsts->host);
	}
}

void mget_hsts_free(mget_hsts_t *hsts)
{
	if (hsts) {
		mget_hsts_deinit(hsts);
		xfree(hsts);
	}
}

mget_hsts_t *mget_hsts_new(const char *host, int port, time_t maxage, int include_subdomains)
{
	mget_hsts_t *hsts = mget_hsts_init(NULL);

	hsts->host = mget_strdup(host);
	hsts->port = port ? port : 443;
	hsts->maxage = maxage;
	hsts->include_subdomains = include_subdomains;

	return hsts;
}

int mget_hsts_host_match(const mget_hsts_db_t *hsts_db, const char *host, int port)
{
	mget_hsts_t hsts, *hstsp;
	const char *p;
	time_t now = time(NULL);

	// first look for an exact match
	hsts.port = port;
	hsts.host = host;
	if ((hstsp = mget_hashmap_get(hsts_db->entries, &hsts)) && hstsp->maxage >= now)
		return 1;

	// now look for a valid subdomain match
	for (p = host; (p = strchr(p, '.')); ) {
		hsts.host = ++p;
		if ((hstsp = mget_hashmap_get(hsts_db->entries, &hsts)) && hstsp->include_subdomains && hstsp->maxage >= now)
			return 1;
	}

	return 0;
}

mget_hsts_db_t *mget_hsts_db_init(mget_hsts_db_t *hsts_db)
{
	if (!hsts_db)
		hsts_db = xmalloc(sizeof(mget_hsts_db_t));

	memset(hsts_db, 0, sizeof(*hsts_db));
	hsts_db->entries = mget_hashmap_create(16, -2, (unsigned int(*)(const void *))_hash_hsts, (int(*)(const void *, const void *))_compare_hsts);
	mget_hashmap_set_key_destructor(hsts_db->entries, (void(*)(void *))mget_hsts_free);
	mget_hashmap_set_value_destructor(hsts_db->entries, (void(*)(void *))mget_hsts_free);
	mget_thread_mutex_init(&hsts_db->mutex);

	return hsts_db;
}

void mget_hsts_db_deinit(mget_hsts_db_t *hsts_db)
{
	if (hsts_db) {
		mget_thread_mutex_lock(&hsts_db->mutex);
		mget_hashmap_free(&hsts_db->entries);
		mget_thread_mutex_unlock(&hsts_db->mutex);
	}
}

void mget_hsts_db_free(mget_hsts_db_t **hsts_db)
{
	if (hsts_db) {
		mget_hsts_db_deinit(*hsts_db);
		xfree(*hsts_db);
	}
}

void mget_hsts_db_add(mget_hsts_db_t *hsts_db, mget_hsts_t *hsts)
{
	mget_thread_mutex_lock(&hsts_db->mutex);

	if (hsts->maxage == 0) {
		if (mget_hashmap_remove(hsts_db->entries, hsts))
			debug_printf("removed HSTS %s:%d\n", hsts->host, hsts->port);
		mget_hsts_free(hsts);
		hsts = NULL;
	} else {
		mget_hsts_t *old = mget_hashmap_get(hsts_db->entries, hsts);

		if (old) {
			if (old->mtime < hsts->mtime) {
				old->mtime = hsts->mtime;
				old->maxage = hsts->maxage;
				old->include_subdomains = hsts->include_subdomains;
				debug_printf("update HSTS %s:%d (maxage=%ld, includeSubDomains=%d)\n", old->host, old->port, old->maxage, old->include_subdomains);
			}
			mget_hsts_free(hsts);
			hsts = NULL;
		} else {
			// key and value are the same to make mget_hashmap_get() return old 'hsts'
			debug_printf("add HSTS %s:%d (maxage=%ld, includeSubDomains=%d)\n", hsts->host, hsts->port, hsts->maxage, hsts->include_subdomains);
			mget_hashmap_put_noalloc(hsts_db->entries, hsts, hsts);
			// no need to free anything here
		}
	}

	mget_thread_mutex_unlock(&hsts_db->mutex);
}

static int G_GNUC_MGET_NONNULL_ALL _hsts_save(FILE *fp, const mget_hsts_t *hsts)
{
	fprintf(fp, "%s %d %ld %d %ld\n", hsts->host, hsts->port, hsts->maxage, hsts->include_subdomains, hsts->mtime);
	return 0;
}

// save the HSTS cache to a flat file
// not thread-save

int mget_hsts_db_save(mget_hsts_db_t *hsts_db, const char *fname)
{
	FILE *fp;
	int ret = -1, size;

	if (!fname || !*fname)
		return -1;

	mget_hsts_db_load(hsts_db, fname);

	if ((size = mget_hashmap_size(hsts_db->entries)) <= 0)
		return -1;

	if ((fp = fopen(fname, "w"))) {
		fputs("#HSTS 1.0 file\n", fp);
		fputs("#Generated by Mget " PACKAGE_VERSION ". Edit at your own risk.\n\n", fp);

		mget_hashmap_browse(hsts_db->entries, (int(*)(void *, const void *, void *))_hsts_save, fp);

		if (!ferror(fp))
			ret = 0;

		if (fclose(fp))
			ret = -1;

		if (ret)
			error_printf(_("Failed to write to HSTS file '%s' (%d)\n"), fname, errno);
		else
			debug_printf(_("saved %d HSTS entr%s into '%s'\n"), size, size != 1 ? "ies" : "y", fname);
	} else
		error_printf(_("Failed to open HSTS file '%s' (%d)\n"), fname, errno);

	return ret;
}

// load the HSTS cache from a flat file
// not thread-save

int mget_hsts_db_load(mget_hsts_db_t *hsts_db, const char *fname)
{
	mget_hsts_t hsts;
	FILE *fp;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	time_t now = time(NULL);
	int ok, nentries = 0;

	if (!hsts_db || !fname || !*fname)
		return 0;

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

			mget_hsts_init(&hsts);
			ok = 0;

			// parse host
			if (*linep) {
				for (p = linep; *linep && !isspace(*linep);) linep++;
				hsts.host = strndup(p, linep - p);
			}

			// parse port
			if (*linep) {
				for (p = ++linep; *linep && !isspace(*linep);) linep++;
				hsts.port = atoi(p);
				if (hsts.port == 0)
					hsts.port = 443;
			}

			// parse max age
			if (*linep) {
				for (p = ++linep; *linep && !isspace(*linep);) linep++;
				hsts.maxage = atol(p);
				if (hsts.maxage < now) {
					// drop expired entry
					mget_hsts_deinit(&hsts);
					continue;
				}
			}

			// parse includeSubDomains
			if (*linep) {
				for (p = ++linep; *linep && !isspace(*linep);) linep++;
				hsts.include_subdomains = atoi(p) ? 1 : 0;
				ok = 1;
			}

			// parse mtime (age of this entry)
			if (*linep) {
				for (p = ++linep; *linep && !isspace(*linep);) linep++;
				hsts.mtime = atol(p);
			}

			if (ok) {
				mget_hsts_db_add(hsts_db, mget_memdup(&hsts, sizeof(hsts)));
			} else {
				mget_hsts_deinit(&hsts);
				error_printf(_("Failed to parse HSTS line: '%s'\n"), buf);
			}
		}

		xfree(buf);
		fclose(fp);

		nentries = mget_hashmap_size(hsts_db->entries);

		debug_printf(_("found %d HSTS entr%s in '%s'\n"), nentries, nentries !=1 ? "ies" : "y", fname);
	} else if (errno != ENOENT)
		error_printf(_("Failed to open HSTS file '%s' (%d)\n"), fname, errno);

	return nentries;
}

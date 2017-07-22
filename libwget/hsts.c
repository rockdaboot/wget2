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
 * HSTS routines
 *
 * Changelog
 * 28.01.2014  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <wget.h>
#include "private.h"

struct _wget_hsts_db_st {
	wget_hashmap_t *
		entries;
	wget_thread_mutex_t
		mutex;
	time_t
		load_time;
};

struct _wget_hsts_st {
	const char *
		host;
	time_t
		expires; // expiry time
	time_t
		created; // creation time
	time_t
		maxage; // max-age in seconds
	int
		port;
	unsigned char
		include_subdomains : 1; // whether or not subdomains are included
};

static unsigned int G_GNUC_WGET_PURE _hash_hsts(const wget_hsts_t *hsts)
{
	unsigned int hash = hsts->port;
	const unsigned char *p;

	for (p = (unsigned char *)hsts->host; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static int G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PURE _compare_hsts(const wget_hsts_t *h1, const wget_hsts_t *h2)
{
	int n;

	if (!(n = strcmp(h1->host, h2->host)))
		return h1->port - h2->port;

	return n;
}

wget_hsts_t *wget_hsts_init(wget_hsts_t *hsts)
{
	if (!hsts)
		hsts = xmalloc(sizeof(wget_hsts_t));

	memset(hsts, 0, sizeof(*hsts));
	hsts->created = time(NULL);

	return hsts;
}

void wget_hsts_deinit(wget_hsts_t *hsts)
{
	if (hsts) {
		xfree(hsts->host);
	}
}

void wget_hsts_free(wget_hsts_t *hsts)
{
	if (hsts) {
		wget_hsts_deinit(hsts);
		xfree(hsts);
	}
}

wget_hsts_t *wget_hsts_new(const char *host, int port, time_t maxage, int include_subdomains)
{
	wget_hsts_t *hsts = wget_hsts_init(NULL);

	hsts->host = wget_strdup(host);
	hsts->port = port ? port : 443;
	hsts->maxage = maxage;
	hsts->expires = maxage ? hsts->created + maxage : 0;
	hsts->include_subdomains = !!include_subdomains;

	return hsts;
}

int wget_hsts_host_match(const wget_hsts_db_t *hsts_db, const char *host, int port)
{
	wget_hsts_t hsts, *hstsp;
	const char *p;
	time_t now = time(NULL);

	// first look for an exact match
	// if it's the default port, "normalize" it
	// we assume the scheme is HTTP
	hsts.port = (port == 80 ? 443 : port);
	hsts.host = host;
	if ((hstsp = wget_hashmap_get(hsts_db->entries, &hsts)) && hstsp->expires >= now)
		return 1;

	// now look for a valid subdomain match
	for (p = host; (p = strchr(p, '.')); ) {
		hsts.host = ++p;
		if ((hstsp = wget_hashmap_get(hsts_db->entries, &hsts)) && hstsp->include_subdomains && hstsp->expires >= now)
			return 1;
	}

	return 0;
}

wget_hsts_db_t *wget_hsts_db_init(wget_hsts_db_t *hsts_db)
{
	if (!hsts_db)
		hsts_db = xmalloc(sizeof(wget_hsts_db_t));

	memset(hsts_db, 0, sizeof(*hsts_db));
	hsts_db->entries = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_hsts, (wget_hashmap_compare_t)_compare_hsts);
	wget_hashmap_set_key_destructor(hsts_db->entries, (wget_hashmap_key_destructor_t)wget_hsts_free);
	wget_hashmap_set_value_destructor(hsts_db->entries, (wget_hashmap_value_destructor_t)wget_hsts_free);
	wget_thread_mutex_init(&hsts_db->mutex);

	return hsts_db;
}

void wget_hsts_db_deinit(wget_hsts_db_t *hsts_db)
{
	if (hsts_db) {
		wget_thread_mutex_lock(&hsts_db->mutex);
		wget_hashmap_free(&hsts_db->entries);
		wget_thread_mutex_unlock(&hsts_db->mutex);
	}
}

void wget_hsts_db_free(wget_hsts_db_t **hsts_db)
{
	if (hsts_db) {
		wget_hsts_db_deinit(*hsts_db);
		xfree(*hsts_db);
	}
}

void wget_hsts_db_add(wget_hsts_db_t *hsts_db, wget_hsts_t *hsts)
{
	wget_thread_mutex_lock(&hsts_db->mutex);

	if (hsts->maxage == 0) {
		if (wget_hashmap_remove(hsts_db->entries, hsts))
			debug_printf("removed HSTS %s:%d\n", hsts->host, hsts->port);
		wget_hsts_free(hsts);
		hsts = NULL;
	} else {
		wget_hsts_t *old = wget_hashmap_get(hsts_db->entries, hsts);

		if (old) {
			if (old->created < hsts->created || old->maxage != hsts->maxage || old->include_subdomains != hsts->include_subdomains) {
				old->created = hsts->created;
				old->expires = hsts->expires;
				old->maxage = hsts->maxage;
				old->include_subdomains = hsts->include_subdomains;
				debug_printf("update HSTS %s:%d (maxage=%lld, includeSubDomains=%d)\n", old->host, old->port, (long long)old->maxage, old->include_subdomains);
			}
			wget_hsts_free(hsts);
			hsts = NULL;
		} else {
			// key and value are the same to make wget_hashmap_get() return old 'hsts'
			// debug_printf("add HSTS %s:%d (maxage=%lld, includeSubDomains=%d)\n", hsts->host, hsts->port, (long long)hsts->maxage, hsts->include_subdomains);
			wget_hashmap_put_noalloc(hsts_db->entries, hsts, hsts);
			// no need to free anything here
		}
	}

	wget_thread_mutex_unlock(&hsts_db->mutex);
}

static int _hsts_db_load(wget_hsts_db_t *hsts_db, FILE *fp)
{
	wget_hsts_t hsts;
	struct stat st;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	time_t now = time(NULL);
	int ok;

	// if the database file hasn't changed since the last read
	// there's no need to reload

	if (fstat(fileno(fp), &st) == 0) {
		if (st.st_mtime != hsts_db->load_time)
			hsts_db->load_time = st.st_mtime;
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

		wget_hsts_init(&hsts);
		ok = 0;

		// parse host
		if (*linep) {
			for (p = linep; *linep && !isspace(*linep); )
				linep++;
			hsts.host = wget_strmemdup(p, linep - p);
		}

		// parse port
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep); )
				linep++;
			hsts.port = atoi(p);
			if (hsts.port == 0)
				hsts.port = 443;
		}

		// parse includeSubDomains
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep); )
				linep++;
			hsts.include_subdomains = atoi(p) ? 1 : 0;
		}

		// parse creation time
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep); )
				linep++;
			hsts.created = (time_t)atoll(p);
		}

		// parse max age
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep); )
				linep++;
			hsts.maxage = (time_t)atoll(p);
			hsts.expires = hsts.maxage ? hsts.created + hsts.maxage : 0;
			if (hsts.expires < now) {
				// drop expired entry
				wget_hsts_deinit(&hsts);
				continue;
			}
			ok = 1;
		}

		if (ok) {
			wget_hsts_db_add(hsts_db, wget_memdup(&hsts, sizeof(hsts)));
		} else {
			wget_hsts_deinit(&hsts);
			error_printf(_("Failed to parse HSTS line: '%s'\n"), buf);
		}
	}

	xfree(buf);

	if (ferror(fp)) {
		hsts_db->load_time = 0; // reload on next call to this function
		return -1;
	}

	return 0;
}

// Load the HSTS cache from a flat file
// Protected by flock()

int wget_hsts_db_load(wget_hsts_db_t *hsts_db, const char *fname)
{
	if (!hsts_db || !fname || !*fname)
		return 0;

	if (wget_update_file(fname, (wget_update_load_t)_hsts_db_load, NULL, hsts_db)) {
		error_printf(_("Failed to read HSTS data\n"));
		return -1;
	} else {
		debug_printf(_("Fetched HSTS data from '%s'\n"), fname);
		return 0;
	}
}

static int G_GNUC_WGET_NONNULL_ALL _hsts_save(FILE *fp, const wget_hsts_t *hsts)
{
	fprintf(fp, "%s %d %d %lld %lld\n", hsts->host, hsts->port, hsts->include_subdomains, (long long)hsts->created, (long long)hsts->maxage);
	return 0;
}

static int _hsts_db_save(void *hsts_db, FILE *fp)
{
	wget_hashmap_t *entries = ((wget_hsts_db_t *)hsts_db)->entries;

	if (wget_hashmap_size(entries) > 0) {
		fputs("#HSTS 1.0 file\n", fp);
		fputs("#Generated by Wget2 " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		fputs("# <hostname> <port> <incl. subdomains> <created> <max-age>\n", fp);

		wget_hashmap_browse(entries, (wget_hashmap_browse_t)_hsts_save, fp);

		if (ferror(fp))
			return -1;
	}

	return 0;
}

// Save the HSTS cache to a flat file
// Protected by flock()

int wget_hsts_db_save(wget_hsts_db_t *hsts_db, const char *fname)
{
	int size;

	if (!hsts_db || !fname || !*fname)
		return -1;

	if (wget_update_file(fname, (wget_update_load_t)_hsts_db_load, _hsts_db_save, hsts_db)) {
		error_printf(_("Failed to write HSTS file '%s'\n"), fname);
		return -1;
	}

	if ((size = wget_hashmap_size(hsts_db->entries)))
		debug_printf(_("Saved %d HSTS entr%s into '%s'\n"), size, size != 1 ? "ies" : "y", fname);
	else
		debug_printf(_("No HSTS entries to save. Table is empty.\n"));

	return 0;
}

/*
 * Copyright (c) 2016-2024 Free Software Foundation, Inc.
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
 * TLS session data cache for TLS resumption
 *
 * Changelog
 * 21.07.2016  Tim Ruehsen  created
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

struct wget_tls_session_db_st {
	wget_hashmap *
		entries;
	wget_thread_mutex
		mutex;
	int64_t
		load_time;
	bool
		changed : 1; // whether or not the db has been changed / needs saving
};

struct wget_tls_session_st {
	const char *
		host;
	int64_t
		expires; // expiry time
	int64_t
		created; // creation time
	int64_t
		maxage; // max-age in seconds
	size_t
		data_size;
	const char *
		data; // session resumption data
};

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
WGET_GCC_PURE
static unsigned int hash_tls_session(const wget_tls_session *tls_session)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)tls_session->host; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

WGET_GCC_NONNULL_ALL WGET_GCC_PURE
static int compare_tls_session(const wget_tls_session *s1, const wget_tls_session *s2)
{
	int n;

	if ((n = strcmp(s1->host, s2->host)))
		return n;

//	if (s1->data_size < s2->data_size)
//		return -1;

//	if (s1->data_size > s2->data_size)
//		return 1;

//	return memcmp(s1->data, s2->data, s1->data_size);
	return 0;
}

wget_tls_session *wget_tls_session_init(wget_tls_session *tls_session)
{
	if (!tls_session) {
		if (!(tls_session = wget_calloc(1, sizeof(wget_tls_session))))
			return NULL;
	} else
		memset(tls_session, 0, sizeof(*tls_session));

	tls_session->created = time(NULL);

	return tls_session;
}

void wget_tls_session_deinit(wget_tls_session *tls_session)
{
	if (tls_session) {
		xfree(tls_session->host);
		xfree(tls_session->data);
	}
}

void wget_tls_session_free(wget_tls_session *tls_session)
{
	if (tls_session) {
		wget_tls_session_deinit(tls_session);
		xfree(tls_session);
	}
}

wget_tls_session *wget_tls_session_new(const char *host, int64_t maxage, const void *data, size_t data_size)
{
	wget_tls_session *tls_session = wget_tls_session_init(NULL);

	if (tls_session) {
		tls_session->host = wget_strdup(host);
		tls_session->data = wget_memdup(data, data_size);
		tls_session->data_size = data_size;

		if (maxage <= 0 || maxage >= INT64_MAX / 2 || tls_session->created < 0 || tls_session->created >= INT64_MAX / 2) {
			tls_session->maxage = 0;
			tls_session->expires = 0;
		} else {
			tls_session->maxage = maxage;
			tls_session->expires = tls_session->created + maxage;
		}
	}

	return tls_session;
}

int wget_tls_session_get(const wget_tls_session_db *tls_session_db, const char *host, void **data, size_t *size)
{
	if (tls_session_db) {
		wget_tls_session tls_session, *tls_sessionp;
		int64_t now = time(NULL);

		tls_session.host = host;
		if (wget_hashmap_get(tls_session_db->entries, &tls_session, &tls_sessionp) && tls_sessionp->expires >= now) {
			if (data)
				*data = wget_memdup(tls_sessionp->data, tls_sessionp->data_size);
			if (size)
				*size = tls_sessionp->data_size;
			return 0;
		}
	}

	return 1;
}

wget_tls_session_db *wget_tls_session_db_init(wget_tls_session_db *tls_session_db)
{
	wget_hashmap *entries = wget_hashmap_create(16, (wget_hashmap_hash_fn *) hash_tls_session, (wget_hashmap_compare_fn *) compare_tls_session);

	if (!entries)
		return NULL;

	if (!tls_session_db) {
		if (!(tls_session_db = wget_calloc(1, sizeof(wget_tls_session_db)))) {
			wget_hashmap_free(&entries);
			return NULL;
		}
	} else
		memset(tls_session_db, 0, sizeof(*tls_session_db));

	wget_hashmap_set_key_destructor(entries, (wget_hashmap_key_destructor *) wget_tls_session_free);
	wget_hashmap_set_value_destructor(entries, (wget_hashmap_value_destructor *) wget_tls_session_free);
	tls_session_db->entries = entries;

	wget_thread_mutex_init(&tls_session_db->mutex);

	return tls_session_db;
}

void wget_tls_session_db_deinit(wget_tls_session_db *tls_session_db)
{
	if (tls_session_db) {
		wget_thread_mutex_lock(tls_session_db->mutex);
		wget_hashmap_free(&tls_session_db->entries);
		wget_thread_mutex_unlock(tls_session_db->mutex);

		wget_thread_mutex_destroy(&tls_session_db->mutex);
	}
}

void wget_tls_session_db_free(wget_tls_session_db **tls_session_db)
{
	if (tls_session_db) {
		wget_tls_session_db_deinit(*tls_session_db);
		xfree(*tls_session_db);
	}
}

void wget_tls_session_db_add(wget_tls_session_db *tls_session_db, wget_tls_session *tls_session)
{
	if (!tls_session_db || !tls_session)
		return;

	wget_thread_mutex_lock(tls_session_db->mutex);

	if (tls_session->maxage == 0) {
		if (wget_hashmap_remove(tls_session_db->entries, tls_session)) {
			tls_session_db->changed = 1;
			debug_printf("removed TLS session data for %s\n", tls_session->host);
		}
		wget_tls_session_free(tls_session);
		tls_session = NULL;
	} else {
		wget_tls_session *old;

		if (wget_hashmap_get(tls_session_db->entries, tls_session, &old)) {
			debug_printf("found TLS session data for %s\n", old->host);
			if (wget_hashmap_remove(tls_session_db->entries, old))
				debug_printf("removed TLS session data for %s\n", tls_session->host);
		}

		debug_printf("add TLS session data for %s (maxage=%lld, size=%zu)\n", tls_session->host, (long long)tls_session->maxage, tls_session->data_size);
		wget_hashmap_put(tls_session_db->entries, tls_session, tls_session);
		tls_session_db->changed = 1;
	}

	wget_thread_mutex_unlock(tls_session_db->mutex);
}

static int tls_session_db_load(wget_tls_session_db *tls_session_db, FILE *fp)
{
	wget_tls_session tls_session;
	struct stat st;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	int64_t now = time(NULL);
	bool ok;

	// if the database file hasn't changed since the last read
	// there's no need to reload

	if (fstat(fileno(fp), &st) == 0) {
		if (st.st_mtime != tls_session_db->load_time)
			tls_session_db->load_time = st.st_mtime;
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

		wget_tls_session_init(&tls_session);
		ok = false;

		// parse host
		if (*linep) {
			for (p = linep; *linep && !isspace(*linep); )
				linep++;
			tls_session.host = wget_strmemdup(p, linep - p);
		}

		// parse creation time
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep); )
				linep++;
			tls_session.created = (int64_t) atoll(p);
			if (tls_session.created < 0 || tls_session.created >= INT64_MAX / 2)
				tls_session.created = 0;
		}

		// parse max age
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep); )
				linep++;
			tls_session.maxage = (int64_t) atoll(p);
			if (tls_session.maxage < 0 || tls_session.maxage >= INT64_MAX / 2)
				tls_session.maxage = 0; // avoid integer overflow here
			tls_session.expires = tls_session.maxage ? tls_session.created + tls_session.maxage : 0;
			if (tls_session.expires < now) {
				// drop expired entry
				wget_tls_session_deinit(&tls_session);
				continue;
			}
		}

		// parse session data
		if (*linep) {
			for (p = ++linep; *linep && !isspace(*linep); )
				linep++;

			size_t len = linep - p;
			char *data = wget_malloc(wget_base64_get_decoded_length(len));
			if (data) {
				tls_session.data_size = wget_base64_decode(data, p, len);
				tls_session.data = data;

				ok = true;
			}
		}

		if (ok) {
			bool no_change = wget_hashmap_size(tls_session_db->entries) == 0;
			wget_tls_session_db_add(tls_session_db, wget_memdup(&tls_session, sizeof(tls_session)));
			if (no_change)
				tls_session_db->changed = 0;
		} else {
			wget_tls_session_deinit(&tls_session);
			error_printf(_("Failed to parse HSTS line: '%s'\n"), buf);
		}
	}

	xfree(buf);

	if (ferror(fp)) {
		tls_session_db->load_time = 0; // reload on next call to this function
		return -1;
	}

	return 0;
}

// Load the TLS session cache from a flat file
// Protected by flock()

int wget_tls_session_db_load(wget_tls_session_db *tls_session_db, const char *fname)
{
	if (!tls_session_db || !fname || !*fname)
		return 0;

	if (wget_update_file(fname, (wget_update_load_fn *) tls_session_db_load, NULL, tls_session_db)) {
		error_printf(_("Failed to read TLS session data\n"));
		return -1;
	} else {
		debug_printf("Fetched TLS session data from '%s'\n", fname);
		return 0;
	}
}

WGET_GCC_NONNULL_ALL
static int tls_session_save(void *_fp, const void *_tls_session, WGET_GCC_UNUSED void *v)
{
	FILE *fp = _fp;
	const wget_tls_session *tls_session = _tls_session;
	char tmp[1024], *session_b64 = tmp;
	size_t b64_len = wget_base64_get_encoded_length(tls_session->data_size);

	if (b64_len > sizeof(tmp)) {
		session_b64 = wget_malloc(b64_len);
		if (!session_b64) {
			error_printf(_("Failed to allocate %zu bytes\n"), b64_len);
			return 0;
		}
	}

	wget_base64_encode(session_b64, (const char *) tls_session->data, tls_session->data_size);

	wget_fprintf(fp, "%s %lld %lld %s\n", tls_session->host, (long long)tls_session->created, (long long)tls_session->maxage, session_b64);

	if (session_b64 != tmp)
		xfree(session_b64);

	return 0;
}

static int tls_session_db_save(void *tls_session_db, FILE *fp)
{
	wget_hashmap *entries = ((wget_tls_session_db *)tls_session_db)->entries;

	if (wget_hashmap_size(entries) > 0) {
		fputs("#TLSSession 1.0 file\n", fp);
		fputs("#Generated by libwget " PACKAGE_VERSION ". Edit at your own risk.\n", fp);
		fputs("#<hostname>  <created> <max-age> <session data>\n\n", fp);

		wget_hashmap_browse(entries, tls_session_save, fp);

		if (ferror(fp))
			return -1;
	}

	return 0;
}

// Save the TLS session cache to a flat file
// Protected by flock()

int wget_tls_session_db_save(wget_tls_session_db *tls_session_db, const char *fname)
{
	int size;

	if (!tls_session_db || !fname || !*fname)
		return -1;

	if (wget_update_file(fname, (wget_update_load_fn *) tls_session_db_load, tls_session_db_save, tls_session_db)) {
		error_printf(_("Failed to write TLS session file '%s'\n"), fname);
		return -1;
	}

	if ((size = wget_hashmap_size(tls_session_db->entries)))
		debug_printf("Saved %d TLS session entr%s into '%s'\n", size, size != 1 ? "ies" : "y", fname);
	else
		debug_printf("No TLS session entries to save. Table is empty.\n");

	tls_session_db->changed = 0;

	return 0;
}

int wget_tls_session_db_changed(wget_tls_session_db *tls_session_db)
{
	return tls_session_db ? tls_session_db->changed : 0;
}

/*
 * Copyright (c) 2012 Tim Ruehsen
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
 * Cookie database routines
 *
 * Changelog
 * 23.10.2012  Tim Ruehsen  created
 *
 * see https://tools.ietf.org/html/rfc6265
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#ifdef WITH_LIBPSL
#  include <libpsl.h>
#endif

#include <wget.h>
#include "private.h"
#include "cookie.h"

struct wget_cookie_db_st {
	wget_vector *
		cookies;
#ifdef WITH_LIBPSL
	psl_ctx_t
		*psl; // libpsl Publix Suffix List context
#endif
	wget_thread_mutex
		mutex;
	unsigned int
		age;
	bool
		keep_session_cookies : 1; // whether or not session cookies are saved
};

// by this kind of sorting, we can easily see if a domain matches or not (match = supercookie !)

int wget_cookie_db_load_psl(wget_cookie_db *cookie_db, const char *fname)
{
#ifdef WITH_LIBPSL
	if (!cookie_db)
		return -1;

	if (fname) {
		psl_ctx_t *psl = psl_load_file(fname);

		psl_free(cookie_db->psl);
		cookie_db->psl = psl;
	} else {
		psl_free(cookie_db->psl);
		cookie_db->psl = NULL;
	}

	return 0;
#else
	(void) cookie_db; (void) fname;
	return -1;
#endif
}

// this is how we sort the entries in a cookie db
WGET_GCC_NONNULL_ALL WGET_GCC_PURE
static int compare_cookie(const wget_cookie *c1, const wget_cookie *c2)
{
	int n;

	if (!(n = wget_strcmp(c1->domain, c2->domain))) {
		if (!(n = wget_strcmp(c1->name, c2->name))) {
			n = wget_strcmp(c1->path, c2->path);
		}
	}

	return n;
}

// this is how we sort the entries when constructing a Cookie: header field
WGET_GCC_NONNULL_ALL WGET_GCC_PURE
static int compare_cookie2(const wget_cookie *c1, const wget_cookie *c2)
{
	// RFC 6265 5.4 demands sorting by 1. longer paths first, 2. earlier creation time first.
	size_t len1 = strlen(c1->path);
	size_t len2 = strlen(c2->path);

	if (len1 < len2)
		return 1;

	if (len1 > len2)
		return -1;

	if (c1->sort_age < c2->sort_age)
		return -1;

	if (c1->sort_age > c2->sort_age)
		return 1;

	return 0;
}

int wget_cookie_check_psl(const wget_cookie_db *cookie_db, const wget_cookie *cookie)
{
//	wget_thread_mutex_lock(&_cookies_mutex);

#ifdef WITH_LIBPSL
	int ret;

	if (cookie_db->psl)
		ret = psl_is_public_suffix(cookie_db->psl, cookie->domain) ? -1 : 0;
	else
		ret = 0;
#else
	(void) cookie_db; (void) cookie;
	int ret = 0;
#endif

//	wget_thread_mutex_unlock(&_cookies_mutex);

	return ret;
}

int wget_cookie_store_cookie(wget_cookie_db *cookie_db, wget_cookie *cookie)
{
	wget_cookie *old;
	int pos;

	if (!cookie)
		return WGET_E_INVALID;

	if (!cookie_db) {
		wget_cookie_free(&cookie);
		return WGET_E_INVALID;
	}

	debug_printf("got cookie %s=%s\n", cookie->name, cookie->value);

	if (!cookie->normalized) {
		debug_printf("cookie '%s' dropped, it wasn't normalized\n", cookie->name);
		wget_cookie_free(&cookie);
		return WGET_E_INVALID;
	}

	if (wget_cookie_check_psl(cookie_db, cookie) != 0) {
		debug_printf("cookie '%s' dropped, domain '%s' is a public suffix\n", cookie->name, cookie->domain);
		wget_cookie_free(&cookie);
		return WGET_E_INVALID;
	}

	wget_thread_mutex_lock(cookie_db->mutex);

	old = wget_vector_get(cookie_db->cookies, pos = wget_vector_find(cookie_db->cookies, cookie));

	if (old) {
		debug_printf("replace old cookie %s=%s\n", cookie->name, cookie->value);
		cookie->creation = old->creation;
		cookie->sort_age = old->sort_age;
		wget_vector_replace(cookie_db->cookies, cookie, pos);
	} else {
		debug_printf("store new cookie %s=%s\n", cookie->name, cookie->value);
		cookie->sort_age = ++cookie_db->age;
		wget_vector_insert_sorted(cookie_db->cookies, cookie);
	}

	wget_thread_mutex_unlock(cookie_db->mutex);

	return WGET_E_SUCCESS;
}

void wget_cookie_store_cookies(wget_cookie_db *cookie_db, wget_vector *cookies)
{
	if (cookie_db) {
		int it;

		for (it = 0; it < wget_vector_size(cookies); it++) {
			wget_cookie *cookie = wget_vector_get(cookies, it);
			wget_cookie_store_cookie(cookie_db, cookie); // takes ownership of 'cookie'
		}

		// remove all 'cookie' entries without free'ing
		wget_vector_clear_nofree(cookies);
	}
}

char *wget_cookie_create_request_header(wget_cookie_db *cookie_db, const wget_iri *iri)
{
	int it, init = 0;
	int64_t now = time(NULL);
	wget_vector *cookies = NULL;
	wget_buffer buf;

	if (!cookie_db || !iri)
		return NULL;

	debug_printf("cookie_create_request_header for host=%s path=%s\n", iri->host, iri->path);

	wget_thread_mutex_lock(cookie_db->mutex);

	for (it = 0; it < wget_vector_size(cookie_db->cookies); it++) {
		wget_cookie *cookie = wget_vector_get(cookie_db->cookies, it);
		if (!cookie)
			continue;

		if (cookie->host_only && strcmp(cookie->domain, iri->host)) {
			debug_printf("cookie host match failed (%s,%s)\n", cookie->domain, iri->host);
			continue;
		}

		if (!cookie->host_only && !cookie_domain_match(cookie->domain, iri->host)) {
			debug_printf("cookie domain match failed (%s,%s)\n", cookie->domain, iri->host);
			continue;
		}

		if (cookie->expires && cookie->expires <= now) {
			debug_printf("cookie expired (%lld <= %lld)\n", (long long)cookie->expires, (long long)now);
			continue;
		}

		if (cookie->secure_only && iri->scheme != WGET_IRI_SCHEME_HTTPS) {
			debug_printf("cookie ignored, not secure\n");
			continue;
		}

		if (!cookie_path_match(cookie->path, iri->path)) {
			debug_printf("cookie path doesn't match (%s, %s)\n", cookie->path, iri->path);
			continue;
		}

		debug_printf("found %s=%s\n", cookie->name, cookie->value);

		if (!cookies)
			cookies = wget_vector_create(16, (wget_vector_compare_fn *) compare_cookie2);

		// collect matching cookies (just pointers, no allocation)
		wget_vector_add(cookies, cookie);
	}

	// sort cookies regarding RFC 6265
	wget_vector_sort(cookies);

	// now create cookie header value
	for (it = 0; it < wget_vector_size(cookies); it++) {
		wget_cookie *cookie = wget_vector_get(cookies, it);
		if (!cookie)
			continue;

		if (!init) {
			wget_buffer_init(&buf, NULL, 128);
			init = 1;
		}

		if (buf.length)
			wget_buffer_printf_append(&buf, "; %s=%s", cookie->name, cookie->value);
		else
			wget_buffer_printf_append(&buf, "%s=%s", cookie->name, cookie->value);
	}

	// free vector with free'ing the content
	wget_vector_clear_nofree(cookies);
	wget_vector_free(&cookies);

	wget_thread_mutex_unlock(cookie_db->mutex);

	return init ? buf.data : NULL;
}

wget_cookie_db *wget_cookie_db_init(wget_cookie_db *cookie_db)
{
	if (!cookie_db) {
		cookie_db = wget_calloc(1, sizeof(wget_cookie_db));
		if (!cookie_db)
			return NULL;
	} else
		memset(cookie_db, 0, sizeof(*cookie_db));

	cookie_db->cookies = wget_vector_create(32, (wget_vector_compare_fn *) compare_cookie);
	wget_vector_set_destructor(cookie_db->cookies, cookie_free);
	wget_thread_mutex_init(&cookie_db->mutex);
#ifdef WITH_LIBPSL
#if ((PSL_VERSION_MAJOR > 0) || (PSL_VERSION_MAJOR == 0 && PSL_VERSION_MINOR >= 16))
	cookie_db->psl = psl_latest(NULL);
#else
	cookie_db->psl = (psl_ctx_t *)psl_builtin();
#endif
#endif

	return cookie_db;
}

void wget_cookie_db_deinit(wget_cookie_db *cookie_db)
{
	if (cookie_db) {
#ifdef WITH_LIBPSL
		psl_free(cookie_db->psl);
		cookie_db->psl = NULL;
#endif
		wget_thread_mutex_lock(cookie_db->mutex);
		wget_vector_free(&cookie_db->cookies);
		wget_thread_mutex_unlock(cookie_db->mutex);
		wget_thread_mutex_destroy(&cookie_db->mutex);
	}
}

void wget_cookie_db_free(wget_cookie_db **cookie_db)
{
	if (cookie_db) {
		wget_cookie_db_deinit(*cookie_db);
		xfree(*cookie_db);
	}
}

void wget_cookie_set_keep_session_cookies(wget_cookie_db *cookie_db, bool keep)
{
	if (cookie_db)
		cookie_db->keep_session_cookies = keep;
}

static int cookie_db_load(wget_cookie_db *cookie_db, FILE *fp)
{
	wget_cookie cookie;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	int64_t now = time(NULL);

	while ((buflen = wget_getline(&buf, &bufsize, fp)) >= 0) {
		linep = buf;

		while (isspace(*linep)) linep++; // ignore leading whitespace
		if (!*linep) continue; // skip empty lines

		wget_cookie_init(&cookie);

		if (*linep == '#') {
			if (strncmp(linep, "#HttpOnly_", 10))
				continue; // skip comments

			linep = linep + 10;
			cookie.http_only = 1;
		} else {
			cookie.http_only = 0;
		}

		// strip off \r\n
		while (buflen > 0 && (buf[buflen-1] == '\n' || buf[buflen-1] == '\r'))
			buf[--buflen] = 0;

		// parse domain
		for (p = linep; *linep && *linep != '\t';) linep++;
		if (*p == '.') {
			p++;
			cookie.domain_dot = 1;
		}
		cookie.domain = wget_strmemdup(p, linep - p);

		// parse inverse host_only (FALSE: host_only=1)
		for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
		cookie.host_only = wget_strncasecmp_ascii(p, "TRUE", 4);

		// parse path
		for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
		if (p != linep)
			cookie.path = wget_strmemdup(p, linep - p);
		else
			cookie.path = wget_strmemdup("/", 1); // allow empty paths

		// parse secure_only
		for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
		cookie.secure_only = !wget_strncasecmp_ascii(p, "TRUE", 4);

		// parse expires
		for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
		cookie.expires = (int64_t) atoll(p);
		if (cookie.expires && cookie.expires <= now) {
			// drop expired cookie
			wget_cookie_deinit(&cookie);
			continue;
		}
		if (!cookie.expires && !cookie_db->keep_session_cookies) {
			// drop session cookies
			wget_cookie_deinit(&cookie);
			continue;
		}

		// parse name
		for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
		if (linep == p) {
			error_printf(_("Incomplete cookie entry: %s\n"), buf);
			wget_cookie_deinit(&cookie);
			continue;
		}
		cookie.name = wget_strmemdup(p, linep - p);

		// parse value, until end of line
		for (p = *linep ? ++linep : linep; *linep;) linep++;
		cookie.value = wget_strmemdup(p, linep - p);

		if (wget_cookie_normalize(NULL, &cookie) == 0 && wget_cookie_check_psl(cookie_db, &cookie) == 0) {
			// The following wget_memdup copies pointers to allocated memory to take ownership of the cookie contents.
			// Thus it needs to be accomplished by wget_cookie_init(&cookie), which is done
			// near the top of the loop.
			wget_cookie_store_cookie(cookie_db, wget_memdup(&cookie, sizeof(cookie)));
		} else
			wget_cookie_deinit(&cookie);
	}

	xfree(buf);

	if (ferror(fp)) {
		return -1;
	}

	return 0;
}

int wget_cookie_db_load(wget_cookie_db *cookie_db, const char *fname)
{
	if (!cookie_db || !fname || !*fname)
		return 0;

	if (wget_update_file(fname, (wget_update_load_fn *) cookie_db_load, NULL, cookie_db)) {
		error_printf(_("Failed to read cookies\n"));
		return -1;
	} else {
		debug_printf("Fetched cookies from '%s'\n", fname);
		return 0;
	}
}

// save the cookie store to a flat file

static int cookie_db_save(wget_cookie_db *cookie_db, FILE *fp)
{
	if (wget_vector_size(cookie_db->cookies) > 0) {
		int it;
		int64_t now = time(NULL);

		fputs("# HTTP Cookie File\n", fp);
		fputs("#Generated by libwget " PACKAGE_VERSION ". Edit at your own risk.\n\n", fp);

		for (it = 0; it < wget_vector_size(cookie_db->cookies); it++) {
			wget_cookie *cookie = wget_vector_get(cookie_db->cookies, it);
			if (!cookie)
				continue;

			if (cookie->persistent) {
				if (cookie->expires <= now)
					continue;
			} else if (!cookie_db->keep_session_cookies)
				continue;

			wget_fprintf(fp, "%s%s%s\t%s\t%s\t%s\t%lld\t%s\t%s\n",
				cookie->http_only ? "#HttpOnly_" : "",
				cookie->domain_dot ? "." : "", // compatibility, irrelevant since RFC 6562
				cookie->domain,
				cookie->host_only ? "FALSE" : "TRUE",
				cookie->path, cookie->secure_only ? "TRUE" : "FALSE",
				(long long)cookie->expires,
				cookie->name, cookie->value);

			if (ferror(fp))
				return -1;
		}
	}

	return 0;
}

// Save the HSTS cache to a flat file
// Protected by flock()

int wget_cookie_db_save(wget_cookie_db *cookie_db, const char *fname)
{
	int size;

	if (!cookie_db || !fname || !*fname)
		return -1;

	if (wget_update_file(fname,
		(wget_update_load_fn *) cookie_db_load,
		(wget_update_save_fn *) cookie_db_save, cookie_db))
	{
		error_printf(_("Failed to write cookie file '%s'\n"), fname);
		return -1;
	}

	if ((size = wget_vector_size(cookie_db->cookies)))
		debug_printf("Saved %d cookie%s into '%s'\n", size, size != 1 ? "s" : "", fname);
	else
		debug_printf("No cookies to save. Table is empty.\n");

	return 0;
}

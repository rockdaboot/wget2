/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * Cookie routines
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
#include <ctype.h>
#include <time.h>
#include <errno.h>
#ifdef WITH_LIBPSL
#	include <libpsl.h>
#  define _U
#else
#  define _U G_GNUC_WGET_UNUSED
#endif

#include <c-ctype.h>

#include <wget.h>
#include "private.h"

struct wget_cookie_st {
	const char *
		name;
	const char *
		value;
	const char *
		domain;
	const char *
		path;
	time_t
		expires; // time of expiration (format YYYYMMDDHHMMSS)
	time_t
		maxage; // like expires, but precedes it if set
	time_t
		last_access;
	time_t
		creation;
	unsigned int
		sort_age; // need for sorting on Cookie: header construction
	unsigned int
		domain_dot : 1; // for compatibility with Netscape cookie format
	unsigned int
		normalized : 1;
	unsigned int
		persistent : 1;
	unsigned int
		host_only : 1;
	unsigned int
		secure_only : 1; // cookie should be used over secure connections only (TLS/HTTPS)
	unsigned int
		http_only : 1; // just use the cookie via HTTP/HTTPS protocol
};

struct wget_cookie_db_st {
	wget_vector_t *
		cookies;
#ifdef WITH_LIBPSL
	psl_ctx_t
		*psl; // libpsl Publix Suffix List context
#endif
	wget_thread_mutex_t
		mutex;
	unsigned int
		age;
	unsigned char
		keep_session_cookies : 1; // whether or not session cookies are saved
};

// by this kind of sorting, we can easily see if a domain matches or not (match = supercookie !)

int wget_cookie_db_load_psl(wget_cookie_db_t *cookie_db _U, const char *fname _U)
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
	return -1;
#endif
}

// this is how we sort the entries in a cookie db
static int G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PURE _compare_cookie(const wget_cookie_t *c1, const wget_cookie_t *c2)
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
static int G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PURE _compare_cookie2(const wget_cookie_t *c1, const wget_cookie_t *c2)
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

static int G_GNUC_WGET_NONNULL_ALL _domain_match(const char *domain, const char *host)
{
	size_t domain_length, host_length;
	const char *p;

	debug_printf("domain_match(%s,%s)", domain, host);

	if (!strcmp(domain, host))
		return 1; // an exact match

	domain_length = strlen(domain);
	host_length = strlen(host);

	if (domain_length >= host_length)
		return 0; // host is too short

	p = host + host_length - domain_length;
	if (!strcmp(p, domain) && p[-1] == '.')
		return 1;

	return 0;
}

static int G_GNUC_WGET_NONNULL((1)) _path_match(const char *cookie_path, const char *request_path)
{
	const char *last_slash;
	size_t cookie_path_length, iri_path_length;

	if (*cookie_path == '/')
		cookie_path++;

	if (request_path && *request_path == '/')
		request_path++;

	debug_printf("path_match(/%s,/%s)\n", cookie_path, request_path ? request_path : "");

	// algorithm as described in RFC 6265 5.1.4

//	if (!request_path || *request_path != '/' || !(last_slash = strrchr(request_path + 1, '/'))) {
//		request_path = "/";
//		iri_path_length = 1;
	if (!request_path || !(last_slash = strrchr(request_path, '/'))) {
		request_path = "";
		iri_path_length = 0;
	} else {
		iri_path_length = last_slash - request_path;
	}

	cookie_path_length = strlen(cookie_path);

	if (iri_path_length < cookie_path_length)
		// cookie-path is not a prefix of request-path
		return 0;

	if (iri_path_length == 0 && cookie_path_length == 0)
		// slash matches slash
		return 1;

	if (!strncmp(cookie_path, request_path, cookie_path_length)) {
		if (!request_path[cookie_path_length])
			// the cookie-path and the request-path are identical
			return 1;

		if (cookie_path[cookie_path_length - 1] == '/')
			// the cookie-path is a prefix of the request-path, and the last
			// character of the cookie-path is %x2F ("/").
			return 1;

		if (request_path[cookie_path_length] == '/')
			// the cookie-path is a prefix of the request-path, and the first
			// character of the request-path that is not included in the cookie-
			// path is a %x2F ("/") character.
			return 1;
	}

	return 0;
}

wget_cookie_t *wget_cookie_init(wget_cookie_t *cookie)
{
	if (!cookie)
		cookie = xcalloc(1, sizeof(wget_cookie_t));
	else
		memset(cookie, 0, sizeof(*cookie));

	cookie->last_access = cookie->creation = time(NULL);

	return cookie;
}

void wget_cookie_deinit(wget_cookie_t *cookie)
{
	if (cookie) {
		xfree(cookie->name);
		xfree(cookie->value);
		xfree(cookie->domain);
		xfree(cookie->path);
	}
}

void wget_cookie_free(wget_cookie_t **cookie)
{
	if (cookie) {
		wget_cookie_deinit(*cookie);
		xfree(*cookie);
	}
}

/*
int wget_cookie_equals(wget_cookie_t *cookie1, wget_cookie_t *cookie2)
{
	if (!cookie1)
		return !cookie2;

	if (!cookie2)
		return 0;

	if (wget_strcmp(cookie1->name, cookie2->name) ||
		wget_strcmp(cookie1->value, cookie2->value) ||
		wget_strcmp(cookie1->domain, cookie2->domain) ||
		wget_strcmp(cookie1->path, cookie2->path) ||
		cookie1->domain_dot != cookie2->domain_dot ||
		cookie1->normalized != cookie2->normalized ||
		cookie1->persistent != cookie2->persistent ||
		cookie1->host_only != cookie2->host_only ||
		cookie1->secure_only != cookie2->secure_only ||
		cookie1->http_only != cookie2->http_only)
	{
		return 0;
	}

	return 1;
}
*/

char *wget_cookie_to_setcookie(wget_cookie_t *cookie)
{
	char expires[32] = "";

	if (!cookie)
		return wget_strdup("(null)");

	if (cookie->expires)
		wget_http_print_date(cookie->expires, expires, sizeof(expires)); // date format from RFC 6265

	return wget_aprintf("%s=%s%s%s%s%s; domain=%s%s%s%s",
		cookie->name, cookie->value,
		*expires ? "; expires=" : "", *expires ? expires : "",
		cookie->path ? "; path=" : "", cookie->path ? cookie->path : "",
		cookie->host_only ? "" : ".", cookie->domain,
		cookie->http_only ? "; HttpOnly" : "",
		cookie->secure_only ? "; Secure" : "");
}

/*
 RFC 6265

 set-cookie-header = "Set-Cookie:" SP set-cookie-string
 set-cookie-string = cookie-pair *( ";" SP cookie-av )
 cookie-pair       = cookie-name "=" cookie-value
 cookie-name       = token
 cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
                       ; US-ASCII characters excluding CTLs,
                       ; whitespace DQUOTE, comma, semicolon,
                       ; and backslash
 token             = <token, defined in [RFC2616], Section 2.2>

 cookie-av         = expires-av / max-age-av / domain-av /
                     path-av / secure-av / httponly-av /
                     extension-av
 expires-av        = "Expires=" sane-cookie-date
 sane-cookie-date  = <rfc1123-date, defined in [RFC2616], Section 3.3.1>
 max-age-av        = "Max-Age=" non-zero-digit *DIGIT
                       ; In practice, both expires-av and max-age-av
                       ; are limited to dates representable by the
                       ; user agent.
 non-zero-digit    = %x31-39
                       ; digits 1 through 9
 domain-av         = "Domain=" domain-value
 domain-value      = <subdomain>
                       ; defined in [RFC1034], Section 3.5, as
                       ; enhanced by [RFC1123], Section 2.1
 path-av           = "Path=" path-value
 path-value        = <any CHAR except CTLs or ";">
 secure-av         = "Secure"
 httponly-av       = "HttpOnly"
 extension-av      = <any CHAR except CTLs or ";">
*/
const char *wget_cookie_parse_setcookie(const char *s, wget_cookie_t **_cookie)
{
	const char *name, *p;
	wget_cookie_t *cookie = wget_cookie_init(NULL);

	// remove leading whitespace from cookie name
	while (c_isspace(*s)) s++;

	// s = wget_http_parse_token(s, &cookie->name);
	// also accept UTF-8 (NON-ASCII) characters in cookie name
	for (p = s; (*s >= 32 && *s <= 126 && *s != '=' && *s != ';') || *s < 0; s++);

	// remove trailing whitespace from cookie name
	while (s > p && c_isspace(s[-1])) s--;
	cookie->name = wget_strmemdup(p, s - p);

	// advance to next delimiter
	while (c_isspace(*s)) s++;

	if (cookie->name && *cookie->name && *s == '=') {
		// *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )

		// skip over delimiter and remove leading whitespace from cookie value
		for (s++; c_isspace(*s);) s++;

/* RFC compliancy is too strict
		if (*s == '\"')
			s++;
		// cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
		for (p = s; *s > 32 && *s <= 126 && *s != '\\' && *s != ',' && *s != ';' && *s != '\"'; s++);
*/

		// also accept UTF-8 (NON-ASCII) characters in cookie value
		for (p = s; (*s >= 32 && *s <= 126 && *s != ';') || *s < 0; s++);

		// remove trailing whitespace from cookie value
		while (s > p && c_isspace(s[-1])) s--;

		cookie->value = wget_strmemdup(p, s - p);

		do {
			// find next delimiter
			while (*s && *s != ';') s++;
			if (!*s) break;

			// skip delimiter and remove leading spaces from attribute name
			for (s++; c_isspace(*s);) s++;
			if (!*s) break;

			s = wget_http_parse_token(s, &name);

			if (name) {
				// find next delimiter
				while (*s && *s != '=' && *s != ';') s++;
				// if (!*s) break;

				if (*s == '=') {
					// find end of value
					for (s++; c_isspace(*s);) s++;
					for (p = s; (*s >= 32 && *s <= 126 && *s != ';') || *s < 0; s++);

					if (!wget_strcasecmp_ascii(name, "expires")) {
						cookie->expires = wget_http_parse_full_date(p);
					} else if (!wget_strcasecmp_ascii(name, "max-age")) {
						long offset = atol(p);

						if (offset > 0) {
							// limit offset to avoid integer overflow
							if (offset > INT_MAX)
								offset = INT_MAX;
							cookie->maxage = time(NULL) + offset;
						} else
							cookie->maxage = 0;
					} else if (!wget_strcasecmp_ascii(name, "domain")) {
						if (p != s) {
							if (*p == '.') { // RFC 6265 5.2.3
								do { p++; } while (*p == '.');
								cookie->domain_dot = 1;
							} else
								cookie->domain_dot = 0;

							// remove trailing whitespace from attribute value
							while (s > p && c_isspace(s[-1])) s--;

							xfree(cookie->domain);
							cookie->domain = wget_strmemdup(p, s - p);
						}
					} else if (!wget_strcasecmp_ascii(name, "path")) {
						// remove trailing whitespace from attribute value
						while (s > p && c_isspace(s[-1])) s--;

						xfree(cookie->path);
						cookie->path = wget_strmemdup(p, s - p);
					} else if (!wget_strcasecmp_ascii(name, "secure")) {
						// here we ignore the value
						cookie->secure_only = 1;
					} else if (!wget_strcasecmp_ascii(name, "httponly")) {
						// here we ignore the value
						cookie->http_only = 1;
					} else {
						debug_printf("Unsupported cookie-av '%s'\n", name);
					}
				} else if (!wget_strcasecmp_ascii(name, "secure")) {
					cookie->secure_only = 1;
				} else if (!wget_strcasecmp_ascii(name, "httponly")) {
					cookie->http_only = 1;
				} else {
					debug_printf("Unsupported cookie-av '%s'\n", name);
				}

				xfree(name);
			}
		} while (*s);

	} else {
		wget_cookie_free(&cookie);
		error_printf("Cookie without name or assignment ignored\n");
	}

	if (_cookie)
		*_cookie = cookie;
	else
		wget_cookie_free(&cookie);

	return s;
}

// normalize/sanitize and store cookies
static int _wget_cookie_normalize_cookie(const wget_iri_t *iri, wget_cookie_t *cookie)
{
/*
	debug_printf("normalize cookie %s=%s\n", cookie->name, cookie->value);
	debug_printf("<  %s=%s\n", cookie->name, cookie->value);
	debug_printf("<  expires=%lld max-age=%lld\n", (long long)cookie->expires, (long long)cookie->maxage);
	debug_printf("<  domain=%s\n", cookie->domain);
	debug_printf("<  path=%s\n", cookie->path);
	debug_printf("<  normalized=%d persistent=%d hostonly=%d secure=%d httponly=%d\n",
		cookie->normalized, cookie->persistent, cookie->host_only, cookie->secure_only, cookie->http_only);
*/
	cookie->normalized = 0;

	if (cookie->maxage)
		cookie->expires = cookie->maxage;

	cookie->persistent = !!cookie->expires;

	// convert domain to lowercase
	wget_strtolower((char *)cookie->domain);

	if (iri) {
		// cookies comes from a HTTP header and needs checking

		// check prefixes as proposed in https://tools.ietf.org/html/draft-ietf-httpbis-cookie-prefixes-00
		if (!wget_strncmp(cookie->name, "__Secure-", 9)) {
			if (!cookie->secure_only || iri->scheme != WGET_IRI_SCHEME_HTTPS) {
				debug_printf("Cookie prefix requires secure origin: %s %s\n", cookie->name, iri->host);
				return -1; // ignore cookie
			}
		}
		else if (!wget_strncmp(cookie->name, "__Host-", 7)) {
			if (!cookie->secure_only || iri->scheme != WGET_IRI_SCHEME_HTTPS) {
				debug_printf("Cookie prefix requires secure origin: %s %s\n", cookie->name, iri->host);
				return -1; // ignore cookie
			}
			if (!cookie->host_only) {
				debug_printf("Cookie prefix requires hostonly flag: %s %s\n", cookie->name, iri->host);
				return -1; // ignore cookie
			}
			if (wget_strcmp(cookie->path, "/")) {
				debug_printf("Cookie prefix requires path \"/\": %s %s\n", cookie->name, iri->host);
				return -1; // ignore cookie
			}
		}

		if (!cookie->domain)
			cookie->domain = wget_strdup("");

		if (*cookie->domain) {
			if (!strcmp(cookie->domain, iri->host)) {
				cookie->host_only = 1;
			} else if (_domain_match(cookie->domain, iri->host)) {
				cookie->host_only = 0;
			} else {
				debug_printf("Domain mismatch: %s %s\n", cookie->domain, iri->host);
				return -1; // ignore cookie
			}
		} else {
			xfree(cookie->domain);
			cookie->domain = wget_strdup(iri->host);
			cookie->host_only = 1;
		}

		if (!cookie->path || *cookie->path != '/') {
			const char *p = iri->path ? strrchr(iri->path, '/') : NULL;

			xfree(cookie->path);

			if (p && p != iri->path) {
				cookie->path = wget_strmemdup(iri->path, p - iri->path);
			} else {
				cookie->path = wget_strdup("/");
				// err_printf(_("Unexpected URI without '/': %s\n"), iri->path);
				// return -1; // ignore cookie
			}
		}
	}

	cookie->normalized = 1;

/*
	debug_printf(">  %s=%s\n", cookie->name, cookie->value);
	debug_printf(">  expires=%lld max-age=%lld\n", (long long)cookie->expires, (long long)cookie->maxage);
	debug_printf(">  domain=%s\n", cookie->domain);
	debug_printf(">  path=%s\n", cookie->path);
	debug_printf(">  normalized=%d persistent=%d hostonly=%d secure=%d httponly=%d\n",
		cookie->normalized, cookie->persistent, cookie->host_only, cookie->secure_only, cookie->http_only);
*/

	return 0;
}

int wget_cookie_normalize(const wget_iri_t *iri, wget_cookie_t *cookie)
{
//	wget_thread_mutex_lock(&_cookies_mutex);

	int ret = _wget_cookie_normalize_cookie(iri, cookie);

//	wget_thread_mutex_unlock(&_cookies_mutex);

	return ret;
}

void wget_cookie_normalize_cookies(const wget_iri_t *iri, const wget_vector_t *cookies)
{
//	wget_thread_mutex_lock(&_cookies_mutex);

	for (int it = 0; it < wget_vector_size(cookies); it++)
		_wget_cookie_normalize_cookie(iri, wget_vector_get(cookies, it));

//	wget_thread_mutex_unlock(&_cookies_mutex);
}

int wget_cookie_check_psl(const wget_cookie_db_t *cookie_db _U, const wget_cookie_t *cookie _U)
{
//	wget_thread_mutex_lock(&_cookies_mutex);

#ifdef WITH_LIBPSL
	int ret;

	if (cookie_db->psl)
		ret = psl_is_public_suffix(cookie_db->psl, cookie->domain) ? -1 : 0;
	else
		ret = 0;
#else
	int ret = 0;
#endif

//	wget_thread_mutex_unlock(&_cookies_mutex);

	return ret;
}

int wget_cookie_store_cookie(wget_cookie_db_t *cookie_db, wget_cookie_t *cookie)
{
	wget_cookie_t *old;
	int pos;

	if (!cookie_db) {
		wget_cookie_deinit(cookie);
		return -1;
	}

	debug_printf("got cookie %s=%s\n", cookie->name, cookie->value);

	if (!cookie->normalized) {
		wget_cookie_deinit(cookie);
		return -1;
	}

	if (wget_cookie_check_psl(cookie_db, cookie) != 0) {
		debug_printf("cookie '%s' dropped, domain '%s' is a public suffix\n", cookie->name, cookie->domain);
		wget_cookie_deinit(cookie);
		return -1;
	}

	wget_thread_mutex_lock(&cookie_db->mutex);

	old = wget_vector_get(cookie_db->cookies, pos = wget_vector_find(cookie_db->cookies, cookie));

	if (old) {
		debug_printf("replace old cookie %s=%s\n", cookie->name, cookie->value);
		cookie->creation = old->creation;
		cookie->sort_age = old->sort_age;
		wget_vector_replace(cookie_db->cookies, cookie, sizeof(*cookie), pos);
	} else {
		debug_printf("store new cookie %s=%s\n", cookie->name, cookie->value);
		cookie->sort_age = ++cookie_db->age;
		wget_vector_insert_sorted(cookie_db->cookies, cookie, sizeof(*cookie));
	}

	wget_thread_mutex_unlock(&cookie_db->mutex);

	return 0;
}

void wget_cookie_store_cookies(wget_cookie_db_t *cookie_db, wget_vector_t *cookies)
{
	if (cookie_db) {
		int it;

		for (it = 0; it < wget_vector_size(cookies); it++) {
			wget_cookie_t *cookie = wget_vector_get(cookies, it);
			wget_cookie_store_cookie(cookie_db, cookie); // stores a shallow copy of 'cookie'
		}

		// shallow free of all 'cookie' entries
		wget_vector_set_destructor(cookies, NULL);
		wget_vector_clear(cookies);
	}
}

char *wget_cookie_create_request_header(wget_cookie_db_t *cookie_db, const wget_iri_t *iri)
{
	int it, init = 0;
	time_t now = time(NULL);
	wget_vector_t *cookies = NULL;
	wget_buffer_t buf;

	if (!cookie_db || !iri)
		return NULL;

	debug_printf("cookie_create_request_header for host=%s path=%s\n", iri->host, iri->path);

	wget_thread_mutex_lock(&cookie_db->mutex);

	for (it = 0; it < wget_vector_size(cookie_db->cookies); it++) {
		wget_cookie_t *cookie = wget_vector_get(cookie_db->cookies, it);

		if (cookie->host_only && strcmp(cookie->domain, iri->host)) {
			debug_printf("cookie host match failed (%s,%s)\n", cookie->domain, iri->host);
			continue;
		}

		if (!cookie->host_only && !_domain_match(cookie->domain, iri->host)) {
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

		if (!_path_match(cookie->path, iri->path)) {
			debug_printf("cookie path doesn't match (%s, %s)\n", cookie->path, iri->path);
			continue;
		}

		debug_printf("found %s=%s\n", cookie->name, cookie->value);

		if (!cookies)
			cookies = wget_vector_create(16, -2, (wget_vector_compare_t)_compare_cookie2);

		// collect matching cookies (just pointers, no allocation)
		wget_vector_add_noalloc(cookies, cookie);
	}

	// sort cookies regarding RFC 6265
	wget_vector_sort(cookies);

	// now create cookie header value
	for (it = 0; it < wget_vector_size(cookies); it++) {
		wget_cookie_t *cookie = wget_vector_get(cookies, it);

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

	wget_thread_mutex_unlock(&cookie_db->mutex);

	return init ? buf.data : NULL;
}

wget_cookie_db_t *wget_cookie_db_init(wget_cookie_db_t *cookie_db)
{
	if (!cookie_db)
		cookie_db = xmalloc(sizeof(wget_cookie_db_t));

	memset(cookie_db, 0, sizeof(*cookie_db));
	cookie_db->cookies = wget_vector_create(32, -2, (wget_vector_compare_t)_compare_cookie);
	wget_vector_set_destructor(cookie_db->cookies, (wget_vector_destructor_t)wget_cookie_deinit);
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

void wget_cookie_db_deinit(wget_cookie_db_t *cookie_db)
{
	if (cookie_db) {
#ifdef WITH_LIBPSL
		psl_free(cookie_db->psl);
		cookie_db->psl = NULL;
#endif
		wget_thread_mutex_lock(&cookie_db->mutex);
		wget_vector_free(&cookie_db->cookies);
		wget_thread_mutex_unlock(&cookie_db->mutex);
	}
}

void wget_cookie_db_free(wget_cookie_db_t **cookie_db)
{
	if (cookie_db) {
		wget_cookie_db_deinit(*cookie_db);
		xfree(*cookie_db);
	}
}

void wget_cookie_set_keep_session_cookies(wget_cookie_db_t *cookie_db, int keep)
{
	if (cookie_db)
		cookie_db->keep_session_cookies = !!keep;
}

static int _cookie_db_load(wget_cookie_db_t *cookie_db, FILE *fp)
{
	wget_cookie_t cookie;
	int ncookies = 0;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	time_t now = time(NULL);

	wget_cookie_init(&cookie);

	while ((buflen = wget_getline(&buf, &bufsize, fp)) >= 0) {
		linep = buf;

		while (isspace(*linep)) linep++; // ignore leading whitespace
		if (!*linep) continue; // skip empty lines

		if (*linep == '#') {
			if (strncmp(linep, "#HttpOnly_", 10))
				continue; // skip comments

			linep = linep + 10;
			cookie.http_only = 1;
		} else {
			cookie.http_only = 0;
		}

		// strip off \r\n
		while (buflen > 0 && (buf[buflen] == '\n' || buf[buflen] == '\r'))
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
		cookie.expires = (time_t)atoll(p);
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
			ncookies++;
			wget_cookie_store_cookie(cookie_db, &cookie);
		} else
			wget_cookie_deinit(&cookie);
	}

	xfree(buf);

	if (ferror(fp)) {
		return -1;
	}

	return ncookies;
}

int wget_cookie_db_load(wget_cookie_db_t *cookie_db, const char *fname)
{
	if (!cookie_db || !fname || !*fname)
		return 0;

	if (wget_update_file(fname, (wget_update_load_t)_cookie_db_load, NULL, cookie_db)) {
		error_printf(_("Failed to read cookies\n"));
		return -1;
	} else {
		debug_printf(_("Fetched cookies from '%s'\n"), fname);
		return 0;
	}
}

// save the cookie store to a flat file

static int _cookie_db_save(wget_cookie_db_t *cookie_db, FILE *fp)
{
	if (wget_vector_size(cookie_db->cookies) > 0) {
		int it;
		time_t now = time(NULL);

		fputs("# HTTP cookie file\n", fp);
		fputs("#Generated by Wget " PACKAGE_VERSION ". Edit at your own risk.\n\n", fp);

		for (it = 0; it < wget_vector_size(cookie_db->cookies); it++) {
			wget_cookie_t *cookie = wget_vector_get(cookie_db->cookies, it);

			if (cookie->persistent) {
				if (cookie->expires <= now)
					continue;
			} else if (!cookie_db->keep_session_cookies)
				continue;

			fprintf(fp, "%s%s%s\t%s\t%s\t%s\t%"PRId64"\t%s\t%s\n",
				cookie->http_only ? "#HttpOnly_" : "",
				cookie->domain_dot ? "." : "", // compatibility, irrelevant since RFC 6562
				cookie->domain,
				cookie->host_only ? "FALSE" : "TRUE",
				cookie->path, cookie->secure_only ? "TRUE" : "FALSE",
				(int64_t)cookie->expires,
				cookie->name, cookie->value);

			if (ferror(fp))
				return -1;
		}
	}

	return 0;
}

// Save the HSTS cache to a flat file
// Protected by flock()

int wget_cookie_db_save(wget_cookie_db_t *cookie_db, const char *fname)
{
	int size;

	if (!cookie_db || !fname || !*fname)
		return -1;

	if (wget_update_file(fname,
		(wget_update_load_t)_cookie_db_load,
		(wget_update_save_t)_cookie_db_save, cookie_db))
	{
		error_printf(_("Failed to write cookie file '%s'\n"), fname);
		return -1;
	}

	if ((size = wget_vector_size(cookie_db->cookies)))
		debug_printf(_("Saved %d cookie%s into '%s'\n"), size, size != 1 ? "s" : "", fname);
	else
		debug_printf(_("No cookies to save. Table is empty.\n"));

	return 0;
}

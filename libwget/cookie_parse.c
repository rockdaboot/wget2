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
 * Cookie parsing routines
 *
 * Changelog
 * 23.10.2012  Tim Ruehsen  created
 * 14.08.2019  Tim Ruehsen  split out from cookie.c
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

#include <c-ctype.h>

#include <wget.h>
#include "private.h"
#include "cookie.h"

bool cookie_domain_match(const char *domain, const char *host)
{
	size_t domain_length, host_length;
	const char *p;

	debug_printf("domain_match(%s,%s)", domain, host);

	if (!strcmp(domain, host))
		return true; // an exact match

	domain_length = strlen(domain);
	host_length = strlen(host);

	if (domain_length >= host_length)
		return false; // host is too short

	p = host + host_length - domain_length;
	if (!strcmp(p, domain) && p[-1] == '.')
		return true;

	return false;
}

bool cookie_path_match(const char *cookie_path, const char *request_path)
{
	const char *last_slash;
	size_t cookie_path_length, iri_path_length;
	bool cookie_path_slash = false;

	if (*cookie_path == '/') {
		cookie_path++;
		cookie_path_slash = true;
	}

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
		return false;

	if (iri_path_length == 0 && cookie_path_length == 0)
		// slash matches slash
		return true;

	if (!strncmp(cookie_path, request_path, cookie_path_length)) {
		if (!request_path[cookie_path_length])
			// the cookie-path and the request-path are identical
			return true;

		if ((cookie_path_length > 0 && cookie_path[cookie_path_length - 1] == '/') || cookie_path_slash)
			// the cookie-path is a prefix of the request-path, and the last
			// character of the cookie-path is %x2F ("/").
			return true;

		if (request_path[cookie_path_length] == '/')
			// the cookie-path is a prefix of the request-path, and the first
			// character of the request-path that is not included in the cookie-
			// path is a %x2F ("/") character.
			return true;
	}

	return false;
}

wget_cookie *wget_cookie_init(wget_cookie *cookie)
{
	if (!cookie) {
		cookie = wget_calloc(1, sizeof(wget_cookie));
		if (!cookie)
			return NULL;
	} else
		memset(cookie, 0, sizeof(*cookie));

	cookie->last_access = cookie->creation = time(NULL);

	return cookie;
}

void wget_cookie_deinit(wget_cookie *cookie)
{
	if (cookie) {
		xfree(cookie->name);
		xfree(cookie->value);
		xfree(cookie->domain);
		xfree(cookie->path);
	}
}

void wget_cookie_free(wget_cookie **cookie)
{
	if (cookie) {
		wget_cookie_deinit(*cookie);
		xfree(*cookie);
	}
}

// for vector destruction
void cookie_free(void *cookie)
{
	if (cookie) {
		wget_cookie_deinit(cookie);
		xfree(cookie);
	}
}

/*
int wget_cookie_equals(wget_cookie *cookie1, wget_cookie *cookie2)
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

char *wget_cookie_to_setcookie(wget_cookie *cookie)
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
const char *wget_cookie_parse_setcookie(const char *s, wget_cookie **_cookie)
{
	const char *name, *p;
	wget_cookie *cookie = wget_cookie_init(NULL);

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

/* RFC compliance is too strict
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
		error_printf(_("Cookie without name or assignment ignored\n"));
	}

	if (_cookie)
		*_cookie = cookie;
	else
		wget_cookie_free(&cookie);

	return s;
}

// normalize/sanitize and store cookies
static int cookie_normalize_cookie(const wget_iri *iri, wget_cookie *cookie)
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
	if (!cookie)
		return -1;

	cookie->normalized = 0;

	if (cookie->maxage)
		cookie->expires = cookie->maxage;

	cookie->persistent = cookie->expires != 0;

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

		if (cookie->domain && *cookie->domain) {
			if (!strcmp(cookie->domain, iri->host)) {
				cookie->host_only = 1;
			} else if (cookie_domain_match(cookie->domain, iri->host)) {
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

int wget_cookie_normalize(const wget_iri *iri, wget_cookie *cookie)
{
//	wget_thread_mutex_lock(&_cookies_mutex);

	int ret = cookie_normalize_cookie(iri, cookie);

//	wget_thread_mutex_unlock(&_cookies_mutex);

	return ret;
}

void wget_cookie_normalize_cookies(const wget_iri *iri, const wget_vector *cookies)
{
//	wget_thread_mutex_lock(&_cookies_mutex);

	for (int it = 0; it < wget_vector_size(cookies); it++)
		cookie_normalize_cookie(iri, wget_vector_get(cookies, it));

//	wget_thread_mutex_unlock(&_cookies_mutex);
}

/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Cookie routines
 *
 * Changelog
 * 23.10.2012  Tim Ruehsen  created
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include "xalloc.h"
#include "utils.h"
#include "iri.h"
#include "log.h"
#include "cookie.h"
#include "options.h"

// #define MAX_LABELS 6 // as of 02.11.2012, we need a value of 4, but having sparse is ok

typedef struct {
	char
		label_buf[40];
	const char
		*label;
	unsigned short
		length;
	unsigned char
		nlabels, // number of labels
		wildcard; // this is a wildcard rule (e.g. *.sapporo.jp)
} PUBLIC_SUFFIX;

static VECTOR
	*cookies,
	*suffixes,
	*suffix_exceptions;
static pthread_mutex_t
	cookies_mutex = PTHREAD_MUTEX_INITIALIZER;
	// no need for a suffix_mutex, it is load once, read many

// by this kind of sorting, we can easily see if a domain matches or not (match = supercookie !)

static int NONNULL_ALL suffix_compare(const PUBLIC_SUFFIX *s1, const PUBLIC_SUFFIX *s2)
{
	int n;

	if ((n = s2->nlabels - s1->nlabels))
		return n; // most labels first

	if ((n=s1->length - s2->length))
		return n;  // shorter rules first

	return strcmp(s1->label, s2->label);
}

static void NONNULL_ALL suffix_init(PUBLIC_SUFFIX *suffix, const char *rule, size_t length)
{
	const char *src;
	char *dst;

	suffix->label = suffix->label_buf;

	if (length >= sizeof(suffix->label_buf) - 1) {
		suffix->nlabels = 0;
		err_printf(_("Suffix rule too long: %s\n"), rule);
		return;
	}

	if (*rule == '*') {
		if (*++rule != '.') {
			suffix->nlabels = 0;
			err_printf(_("Unsupported kind of rule : %s\n"), rule);
			return;
		}
		rule++;
		suffix->wildcard = 1;
		suffix->length = (unsigned char)length - 2;
	} else {
		suffix->wildcard = 0;
		suffix->length = (unsigned char)length;
	}

	suffix->nlabels = 1;

	for (dst = suffix->label_buf, src = rule; *src;) {
		if (*src == '.')
			suffix->nlabels++;
		*dst++ = tolower(*src++);
	}
	*dst = 0;
}

/*
static void NONNULL_ALL suffix_print(PUBLIC_SUFFIX *suffix)
{
	info_printf("[%d] %d %s (%d)\n", suffix->nlabels, suffix->wildcard, suffix->label, suffix->length);
}
*/

int cookie_suffix_match(const char *domain)
{
	PUBLIC_SUFFIX suffix, *rule;
	const char *p, *label_bak;
	unsigned short length_bak;

	// this function should be called without leading dots, just make shure
	suffix.label = domain + (*domain == '.');
	suffix.length = strlen(suffix.label);
	suffix.wildcard = 0;
	suffix.nlabels = 1;

	for (p = suffix.label; *p; p++)
		if (*p == '.')
			suffix.nlabels++;

	// if domain has enough labels, it won't match
	rule = vec_get(suffixes, 0);
	if (!rule || rule->nlabels < suffix.nlabels - 1)
		return 0;

	rule = vec_get(suffixes, vec_find(suffixes, &suffix));
	if (rule) {
		// definitely a match, no matter if the found rule is a wildcard or not
		return 1;
	}

	label_bak = suffix.label;
	length_bak = suffix.length;

	if ((suffix.label = strchr(suffix.label, '.'))) {
		suffix.label++;
		suffix.length = strlen(suffix.label);
		suffix.nlabels--;

		rule = vec_get(suffixes, vec_find(suffixes, &suffix));
		if (rule) {
			if (rule->wildcard) {
				// now that we matched a wildcard, we have to check for an exception
				suffix.label = label_bak;
				suffix.length = length_bak;
				suffix.nlabels++;

				rule = vec_get(suffix_exceptions, vec_find(suffix_exceptions, &suffix));
				if (rule)
					return 0;

				return 1;
			}
		}
	}

	return 0;
}

int cookie_load_public_suffixes(const char *fname)
{
	PUBLIC_SUFFIX suffix, *suffixp;
	FILE *fp;
	int nsuffixes = 0;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;

	// as of 02.11.2012, the list at http://publicsuffix.org/list/ contains ~6000 rules
	// and 40 exceptions.
	if (!suffixes)
		suffixes = vec_create(6*1024, -2, (int(*)(const void *, const void *))suffix_compare);
	if (!suffix_exceptions)
		suffix_exceptions = vec_create(64, -2, (int(*)(const void *, const void *))suffix_compare);

	if ((fp = fopen(fname, "r"))) {
		while ((buflen = getline(&buf, &bufsize, fp)) >= 0) {
			linep = buf;

			while (isspace(*linep)) linep++; // ignore leading whitespace
			if (!*linep) continue; // skip empty lines

			if (*linep == '/' && linep[1] == '/')
				continue; // skip comments

			// parse suffix rule
			for (p = linep; *linep && !isspace(*linep);) linep++;
			*linep = 0;
			if (*p == '!') {
				// add to exceptions
				suffix_init(&suffix, p + 1, linep - p - 1);
				suffixp = vec_get(suffix_exceptions, vec_add(suffix_exceptions, &suffix, sizeof(suffix)));
			} else {
				suffix_init(&suffix, p, linep - p);
				suffixp = vec_get(suffixes, vec_add(suffixes, &suffix, sizeof(suffix)));
			}

			if (suffixp)
				suffixp->label = suffixp->label_buf; // set label to changed address

			nsuffixes++;;
		}

		xfree(buf);
		fclose(fp);

		vec_sort(suffix_exceptions);
		vec_sort(suffixes);

	} else
		err_printf(_("Failed to open public suffix file '%s'\n"), fname);

	return nsuffixes;
}

/*
static int cookie_free_public_suffix(PUBLIC_SUFFIX *suffix)
{
	return 0;
}
*/

void cookie_free_public_suffixes(void)
{
//	vec_browse(suffixes, (int (*)(void *))cookie_free_suffix);
	vec_free(&suffixes);

//	vec_browse(suffix_exceptions, (int (*)(void *))cookie_free_suffix);
	vec_free(&suffix_exceptions);
}

static int NONNULL_ALL compare_cookie(const HTTP_COOKIE *c1, const HTTP_COOKIE *c2)
{
	int n;

	if (!(n = strcmp(c1->domain, c2->domain))) {
		if (!(n = strcasecmp(c1->name, c2->name))) {
			n = strcasecmp(c1->path, c2->path);
		}
	}

	return n;
}

static int NONNULL_ALL domain_match(const char *domain, const char *host)
{
	size_t domain_length, host_length;
	const char *p;

	log_printf("domain_match(%s,%s)", domain, host);

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

static int NONNULL(1) path_match(const char *cookie_path, const char *request_path)
{
	const char *last_slash;
	size_t cookie_path_length, iri_path_length;

	log_printf("path_match(%s,%s)", cookie_path, request_path);

	// algorithm as described in RFC 6265 5.1.4

	if (!request_path || *request_path != '/' || !(last_slash = strrchr(request_path + 1, '/'))) {
		request_path = "/";
		iri_path_length = 1;
	} else {
		iri_path_length = last_slash - request_path;
	}

	cookie_path_length = strlen(cookie_path);

	if (iri_path_length < cookie_path_length)
		// cookie-path is not a prefix of request-path
		return 0;

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

void cookie_init_cookie(HTTP_COOKIE *cookie)
{
	memset(cookie, 0, sizeof(*cookie));
	cookie->last_access = cookie->creation = time(NULL);
}

int cookie_free_cookie(HTTP_COOKIE *cookie)
{
	xfree(cookie->name);
	xfree(cookie->value);
	xfree(cookie->domain);
	xfree(cookie->path);

	return 0;
}

void cookie_free_cookies(void)
{
	pthread_mutex_lock(&cookies_mutex);
	vec_browse(cookies, (int (*)(void *))cookie_free_cookie);
	vec_free(&cookies);
	pthread_mutex_unlock(&cookies_mutex);
}

// normalize/sanitize and store cookies
int cookie_normalize_cookie(const IRI *iri, HTTP_COOKIE *cookie)
{
/*
	log_printf("normalize cookie %s=%s\n", cookie->name, cookie->value);
	log_printf("<  %s=%s\n", cookie->name, cookie->value);
	log_printf("<  expires=%ld max-age=%ld\n", cookie->expires, cookie->maxage);
	log_printf("<  domain=%s\n", cookie->domain);
	log_printf("<  path=%s\n", cookie->path);
	log_printf("<  normalized=%d persistent=%d hostonly=%d secure=%d httponly=%d\n",
		cookie->normalized, cookie->persistent, cookie->host_only, cookie->secure_only, cookie->http_only);
*/
	cookie->normalized = 0;

	if (cookie->maxage)
		cookie->expires = cookie->maxage;

	cookie->persistent = !!cookie->expires;

	if (cookie->domain) {
		char *p;

		// convert domain to lowercase
		for (p = (char *)cookie->domain; *p; p++)
			if (isupper(*p))
				*p = tolower(*p);
	}

	if (iri) {
		// cookies comes from a HTTP header and needs checking
		if (!cookie->domain)
			cookie->domain = strdup("");

		// respect http://publicsuffix.org/list/ to avoid "supercookies"
		if (vec_size(suffixes) > 0 && cookie_suffix_match(cookie->domain)) {
			info_printf("Supercookie %s not accepted\n", cookie->domain);
			return 0;
		}

		if (*cookie->domain) {
			if (domain_match(cookie->domain, iri->host)) {
				cookie->host_only = 0;
			} else {
				log_printf("Domain mismatch: %s %s\n", cookie->domain, iri->host);
				return 0; // ignore cookie
			}
		} else {
			xfree(cookie->domain);
			cookie->domain = strdup(iri->host);
			cookie->host_only = 1;
		}

		if (!cookie->path || *cookie->path != '/') {
			const char *p = iri->path ? strrchr(iri->path, '/') : NULL;

			if (p && p != iri->path) {
				cookie->path = strndup(iri->path, p - iri->path);
			} else {
				cookie->path = strdup("/");
				// err_printf(_("Unexpected URI without '/': %s\n"), iri->path);
				// return 0; // ignore cookie
			}
		}
	}

	cookie->normalized = 1;

/*
	log_printf(">  %s=%s\n", cookie->name, cookie->value);
	log_printf(">  expires=%ld max-age=%ld\n", cookie->expires, cookie->maxage);
	log_printf(">  domain=%s\n", cookie->domain);
	log_printf(">  path=%s\n", cookie->path);
	log_printf(">  normalized=%d persistent=%d hostonly=%d secure=%d httponly=%d\n",
		cookie->normalized, cookie->persistent, cookie->host_only, cookie->secure_only, cookie->http_only);
*/

	return 1;
}

void cookie_normalize_cookies(const IRI *iri, const VECTOR *cookies)
{
	int it;

	for (it = 0; it < vec_size(cookies); it++)
		cookie_normalize_cookie(iri, vec_get(cookies, it));
}

void cookie_store_cookie(HTTP_COOKIE *cookie)
{
	HTTP_COOKIE *old;
	int pos;

	log_printf("got cookie %s=%s\n", cookie->name, cookie->value);

	if (!cookie->normalized)
		return;

	pthread_mutex_lock(&cookies_mutex);

	if (!cookies) {
		cookies = vec_create(128, -2, (int(*)(const void *, const void *))compare_cookie);
		old = NULL;
	} else
		old = vec_get(cookies, pos = vec_find(cookies, cookie));

	if (old) {
		log_printf("replace old cookie %s=%s\n", cookie->name, cookie->value);
		cookie->creation = old->creation;
		cookie_free_cookie(old);
		vec_replace(cookies, cookie, sizeof(*cookie), pos);
	} else {
		log_printf("store new cookie %s=%s\n", cookie->name, cookie->value);
		vec_insert_sorted(cookies, cookie, sizeof(*cookie));
	}

	pthread_mutex_unlock(&cookies_mutex);
}

void cookie_store_cookies(VECTOR *cookies)
{
	int it;

	for (it = vec_size(cookies) - 1; it >= 0; it--) {
		HTTP_COOKIE *cookie = vec_get(cookies, it);
		cookie_store_cookie(cookie);
		vec_remove(cookies, it);
	}
}

char *cookie_create_request_header(const IRI *iri)
{
	int it, init = 0;
	time_t now = time(NULL);
	buffer_t buf;

	log_printf("cookie_create_request_header for host=%s path=%s\n",iri->host,iri->path);

	pthread_mutex_lock(&cookies_mutex);

	for (it = 0; it < vec_size(cookies); it++) {
		HTTP_COOKIE *cookie = vec_get(cookies, it);

		if (((!cookie->host_only && domain_match(cookie->domain, iri->host)) ||
			(cookie->host_only && !strcasecmp(cookie->domain, iri->host))) &&
			(!cookie->expires || cookie->expires >= now) &&
			(!cookie->secure_only || (cookie->secure_only && iri->scheme == IRI_SCHEME_HTTPS)) &&
			path_match(cookie->path, iri->path))
		{
			if (!init) {
				buffer_init(&buf, NULL, 128);
				init = 1;
			}

			if (buf.length)
				buffer_printf_append2(&buf, "; %s=%s", cookie->name, cookie->value);
			else
				buffer_printf_append2(&buf, "%s=%s", cookie->name, cookie->value);
		}
	}

	pthread_mutex_unlock(&cookies_mutex);

	return init ? buf.data : NULL;
}

// save the cookie store to a flat file

int cookie_save(const char *fname, int keep_session_cookies)
{
	FILE *fp;
	int it, ret = -1;
	time_t now = time(NULL);

	info_printf(_("saving cookies to '%s'\n"), fname);

	if ((fp = fopen(fname, "w"))) {
		fputs("# HTTP cookie file\n", fp);
		fputs("#Generated by Mget " MGET_VERSION ". Edit at your own risk.\n\n", fp);

		pthread_mutex_lock(&cookies_mutex);

		for (it = 0; it < vec_size(cookies) && !ferror(fp); it++) {
			HTTP_COOKIE *cookie = vec_get(cookies, it);

			if (cookie->persistent) {
				if (cookie->expires < now)
					continue;
			} else if (!keep_session_cookies)
				continue;

			fprintf(fp, "%s%s%s\t%s\t%s\t%s\t%ld\t%s\t%s\n",
				cookie->http_only ? "#HttpOnly_" : "",
				cookie->domain_dot ? "." : "", // compatibility, irrelevant since RFC 6562
				cookie->domain,
				cookie->host_only ? "FALSE" : "TRUE",
				cookie->path, cookie->secure_only ? "TRUE" : "FALSE",
				cookie->expires,
				cookie->name, cookie->value);
		}

		pthread_mutex_unlock(&cookies_mutex);

		if (!ferror(fp))
			ret = 0;

		if (fclose(fp))
			ret = -1;

		if (ret)
			err_printf(_("Failed to write to cookie file '%s': %s\n"), fname, strerror(errno));

	} else
		err_printf(_("Failed to open cookie file '%s': %s\n"), fname, strerror(errno));

	return ret;
}

int cookie_load(const char *fname)
{
	HTTP_COOKIE cookie;
	FILE *fp;
	int ncookies = 0;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;
	time_t now = time(NULL);

	if ((fp = fopen(fname, "r"))) {
		cookie_init_cookie(&cookie);

		pthread_mutex_lock(&cookies_mutex);

		while ((buflen = getline(&buf, &bufsize, fp)) >= 0) {
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
			cookie.domain = strndup(p, linep - p);

			// parse inverse host_only (FALSE: host_only=1)
			for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
			cookie.host_only = strncasecmp(p, "TRUE", 4);

			// parse path
			for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
			if (p != linep)
				cookie.path = strndup(p, linep - p);
			else
				cookie.path = strdup("/"); // allow empty paths

			// parse secure_only
			for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
			cookie.secure_only = !strncasecmp(p, "TRUE", 4);

			// parse expires
			for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
			cookie.expires = atol(p);
			if (cookie.expires && cookie.expires < now) {
				// drop expired cookie
				cookie_free_cookie(&cookie);
				continue;
			}
			if (!cookie.expires && !config.keep_session_cookies) {
				// drop session cookies
				cookie_free_cookie(&cookie);
				continue;
			}

			// parse name
			for (p = *linep ? ++linep : linep; *linep && *linep != '\t';) linep++;
			if (linep == p) {
				err_printf(_("Incomplete entry in '%s': %s\n"), fname, buf);
				cookie_free_cookie(&cookie);
				continue;
			}
			cookie.name = strndup(p, linep - p);

			// parse value, until end of line
			for (p = *linep ? ++linep : linep; *linep;) linep++;
			cookie.value = strndup(p, linep - p);

			if (cookie_normalize_cookie(NULL, &cookie) != 0) {
				ncookies++;
				cookie_store_cookie(&cookie);
			} else
				cookie_free_cookie(&cookie);
		}

		pthread_mutex_unlock(&cookies_mutex);

		xfree(buf);
		fclose(fp);
	} else
		err_printf(_("Failed to open cookie file '%s'\n"), fname);

	info_printf(_("loaded %d cookie%s from '%s'\n"), ncookies, ncookies !=1 ? "s" : "", fname);

	return ncookies;
}

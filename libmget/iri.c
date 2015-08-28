/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * URI/IRI routines
 * about encoding see http://nikitathespider.com/articles/EncodingDivination.html
 * about GET encoding see http://stackoverflow.com/questions/1549213/whats-the-correct-encoding-of-http-get-request-strings
 * RFC 3986: URI generic syntax
 *
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <libmget.h>
#include "private.h"

static const char
	*default_page = "index.html";
static size_t
	default_page_length = 10;

const char
	* const mget_iri_schemes[] = { "http", "https", NULL },
	* const iri_ports[]   = { "80",   "443" };

#define IRI_CTYPE_GENDELIM (1<<0)
#define _iri_isgendelim(c) (iri_ctype[(unsigned char)(c)]&IRI_CTYPE_GENDELIM)

#define IRI_CTYPE_SUBDELIM (1<<1)
#define _iri_issubdelim(c) (iri_ctype[(unsigned char)(c)]&IRI_CTYPE_SUBDELIM)

#define IRI_CTYPE_UNRESERVED (1<<2)
#define _iri_isunreserved(c) (iri_ctype[(unsigned char)(c)]&IRI_CTYPE_UNRESERVED)

#define _iri_isscheme(c) (isalnum(c) || c == '+' || c == '-' || c == '.')

static const unsigned char
	iri_ctype[256] = {
		[':'] = IRI_CTYPE_GENDELIM,
		['/'] = IRI_CTYPE_GENDELIM,
		['?'] = IRI_CTYPE_GENDELIM,
		['#'] = IRI_CTYPE_GENDELIM,
		['['] = IRI_CTYPE_GENDELIM,
		[']'] = IRI_CTYPE_GENDELIM,
		['@'] = IRI_CTYPE_GENDELIM,

		['!'] = IRI_CTYPE_SUBDELIM,
		['$'] = IRI_CTYPE_SUBDELIM,
		['&'] = IRI_CTYPE_SUBDELIM,
//		['\\'] = IRI_CTYPE_SUBDELIM,
		['\''] = IRI_CTYPE_SUBDELIM,
		['('] = IRI_CTYPE_SUBDELIM,
		[')'] = IRI_CTYPE_SUBDELIM,
		['*'] = IRI_CTYPE_SUBDELIM,
		['+'] = IRI_CTYPE_SUBDELIM,
		[','] = IRI_CTYPE_SUBDELIM,
		[';'] = IRI_CTYPE_SUBDELIM,
		['='] = IRI_CTYPE_SUBDELIM,

		['-'] = IRI_CTYPE_UNRESERVED,
		['.'] = IRI_CTYPE_UNRESERVED,
		['_'] = IRI_CTYPE_UNRESERVED,
		['~'] = IRI_CTYPE_UNRESERVED
	};

int mget_iri_supported(const mget_iri_t *iri)
{
	int it;

	for (it = 0; mget_iri_schemes[it]; it++) {
		if (mget_iri_schemes[it] == iri->scheme)
			return 1;
	}

	return 0;
}

int mget_iri_isgendelim(char c)
{
	// return strchr(":/?#[]@",c)!=NULL;
	return _iri_isgendelim(c);
}

int mget_iri_issubdelim(char c)
{
	// return strchr("!$&\'()*+,;=",c)!=NULL;
	return _iri_issubdelim(c);
}

int mget_iri_isreserved(char c)
{
	return mget_iri_isgendelim(c) || mget_iri_issubdelim(c);
}

int mget_iri_isunreserved(char c)
{
	return c > 32 && c < 127 && (isalnum(c) || _iri_isunreserved(c));
}

int mget_iri_isunreserved_path(char c)
{
	return c > 32 && c < 127 && (isalnum(c) || _iri_isunreserved(c) || c == '/');
}

// needed as helper for blacklist.c/blacklist_free()
void mget_iri_free_content(mget_iri_t *iri)
{
	if (iri) {
		if (iri->host_allocated)
			xfree(iri->host);
		xfree(iri->connection_part);
	}
}

void mget_iri_free(mget_iri_t **iri)
{
	if (iri && *iri) {
		mget_iri_free_content(*iri);
		xfree(*iri);
	}
}

// URIs are assumed to be unescaped at this point

mget_iri_t *mget_iri_parse(const char *url, const char *encoding)
{
	mget_iri_t *iri;
	const char *default_port = NULL;
	char *p, *s, *authority, c;
	size_t slen, it;
	int url_allocated, maybe_scheme;

	if (!url)
		return NULL;

	/*
		URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
		hier-part   = "//" authority path-abempty / path-absolute / path-rootless / path-empty
		scheme      =  ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	 */
	while (isspace(*url)) url++;
	if (!*url) return NULL;

	// first unescape, than convert to UTF-8
	if (strchr(url, '%')) {
		char *unesc_url = strdup(url);

		mget_percent_unescape(unesc_url);

		if (mget_str_needs_encoding(unesc_url)) {
			if ((url = mget_str_to_utf8(unesc_url, encoding)))
				xfree(unesc_url);
			else
				url = unesc_url; // on error, use what we have
		} else
			url = unesc_url;

		url_allocated = 1;
	} else {
		url_allocated = 0;

		if (mget_str_needs_encoding(url)) {
			if ((s = mget_str_to_utf8(url, encoding))) {
				url = s;
				url_allocated = 1;
			}
		}
	}

	// just use one block of memory for all parsed URI parts
	slen = strlen(url);
	iri = xmalloc(sizeof(mget_iri_t) + slen * 2 + 2);
	memset(iri, 0, sizeof(mget_iri_t));
	strcpy(((char *)iri) + sizeof(mget_iri_t), url);
	iri->uri = ((char *)iri) + sizeof(mget_iri_t);
	s = ((char *)iri) + sizeof(mget_iri_t) + slen + 1;
	strcpy(s, url);
	if (url_allocated)
		xfree(url);

	p = s;
	if (isalpha(*p)) {
		maybe_scheme = 1;
		while (*s && !_iri_isgendelim(*s)) {
			if (maybe_scheme && !_iri_isscheme(*s))
				maybe_scheme = 0;
			s++;
		}
	} else
		maybe_scheme = 0;

	if (maybe_scheme && (*s == ':' && (s[1] == '/' || s[1] == 0))) {
		// found a scheme
		*s++ = 0;

		// find the scheme in our static list of supported schemes
		// for later comparisons we compare pointers (avoiding strcasecmp())
		iri->scheme = p;
		for (it = 0; mget_iri_schemes[it]; it++) {
			if (!mget_strcasecmp_ascii(mget_iri_schemes[it], p)) {
				iri->scheme = mget_iri_schemes[it];
				default_port = iri_ports[it];
				break;
			}
		}

		if (iri->scheme == p) {
			// convert scheme to lowercase
			mget_strtolower((char *)iri->scheme);
		}

	} else {
		iri->scheme = MGET_IRI_SCHEME_DEFAULT;
		default_port = iri_ports[0]; // port 80
		s = p; // rewind
	}

	// this is true for http, https, ftp, file
	if (s[0] == '/' && s[1] == '/')
		s += 2;

	// authority
	authority = s;
	while (*s && *s != '/' && *s != '?' && *s != '#')
		s++;
	c = *s;
	if (c) *s++ = 0;

	// left over: [path][?query][#fragment]
	if (c == '/') {
		iri->path = s;
		while (*s && *s != '?' && *s != '#')
			s++;
		c = *s;
		if (c) *s++ = 0;
	}

	if (c == '?') {
		iri->query = s;
		while (*s && *s != '#')
			s++;
		c = *s;
		if (c) *s++ = 0;
	}

	if (c == '#') {
		iri->fragment = s;
		s += strlen(s);
	}

	if (*s) {
		debug_printf("unparsed rest '%s'\n", s);
	}

	if (*authority) {
		s = authority;
		p = strchr(authority, '@');
		if (p) {
			iri->userinfo = s;
			*p = 0;
			s = p + 1;
		}
		if (*s == '[') {
			p = strrchr(s, ']');
			if (p) {
				iri->host = s + 1;
				*p = 0;
				s = p + 1;
			} else {
				// something is broken
				iri->host = s + 1;
				s += strlen(s);
			}
		} else {
			iri->host = s;
			while (*s && *s != ':')
				s++;
		}
		if (*s == ':') {
			if (s[1]) {
				if (!default_port || (strcmp(s + 1, default_port) && atoi(s + 1) != atoi(default_port)))
					iri->port = s + 1;
			}
		}
		*s = 0;
 	}

	iri->resolv_port = iri->port ? iri->port : default_port;

	// now unescape all components (not interested in display, userinfo, password)
	if (iri->host) {
		mget_strtolower((char *)iri->host);
		if ((p = (char *)mget_str_to_ascii(iri->host)) != iri->host) {
			iri->host = p;
			iri->host_allocated = 1;
		}
	}
	else {
		if (iri->scheme == MGET_IRI_SCHEME_HTTP || iri->scheme == MGET_IRI_SCHEME_HTTPS) {
			error_printf(_("Missing host/domain in URI '%s'\n"), iri->uri);
			mget_iri_free(&iri);
			return NULL;
		}
	}

/*
	debug_printf("scheme=%s\n",iri->scheme);
	debug_printf("host=%s\n",iri->host);
	debug_printf("path=%s\n",iri->path);
	debug_printf("query=%s\n",iri->query);
	debug_printf("fragment=%s\n",iri->fragment);
*/

	return iri;
}

mget_iri_t *mget_iri_clone(mget_iri_t *iri)
{
	if (!iri)
		return NULL;

	size_t slen = iri->uri ? strlen(iri->uri) : 0;
	mget_iri_t *clone = mget_memdup(iri, sizeof(mget_iri_t) + slen * 2 + 2);

	clone->connection_part = mget_strdup(iri->connection_part);

	// adjust pointers
	if (iri->host_allocated)
		clone->host = strdup(iri->host);
	else
		clone->host = iri->host ? (char *)clone + (size_t) (iri->host - (const char *)iri) : NULL;

	clone->uri = iri->uri ? (char *)clone + (size_t) (iri->uri - (const char *)iri) : NULL;
	clone->display = iri->display ? (char *)clone + (size_t) (iri->display - (const char *)iri): NULL;
	// not adjust scheme, it is a pointer to a static string
	clone->userinfo = iri->userinfo ? (char *)clone + (size_t) (iri->userinfo - (const char *)iri): NULL;
	clone->password = iri->password ? (char *)clone + (size_t) (iri->password - (const char *)iri): NULL;
	clone->port = iri->port ? (char *)clone + (size_t) (iri->port - (const char *)iri): NULL;
	clone->resolv_port = iri->resolv_port ? (char *)clone + (size_t) (iri->resolv_port - (const char *)iri): NULL;
	clone->path = iri->path ? (char *)clone + (size_t) (iri->path - (const char *)iri): NULL;
	clone->query = iri->query ? (char *)clone + (size_t) (iri->query - (const char *)iri): NULL;
	clone->fragment = iri->fragment ? (char *)clone + (size_t) (iri->fragment - (const char *)iri): NULL;

	return clone;
}

static char *_iri_build_connection_part(mget_iri_t *iri)
{
	char *tag;
	size_t len;

	if (iri->port) {
		len = strlen(iri->scheme) + strlen(iri->host) + strlen(iri->port) + 4 + 1;
		tag = xmalloc(len);

		sprintf(tag, "%s://%s:%s", iri->scheme, iri->host, iri->port);
	} else {
		len = strlen(iri->scheme) + strlen(iri->host) + 3 + 1;
		tag = xmalloc(len);

		sprintf(tag, "%s://%s", iri->scheme, iri->host);
	}

	return tag;
}

const char *mget_iri_get_connection_part(mget_iri_t *iri)
{
	if (iri) {
		if (!iri->connection_part)
			iri->connection_part = _iri_build_connection_part(iri);

		return iri->connection_part;
	}

	return NULL;
}

// normalize /../ and remove /./

static size_t G_GNUC_MGET_NONNULL_ALL _normalize_path(char *path)
{
	char *p1 = path, *p2 = path;

	debug_printf("path %s ->\n", path);

	// skip ./ and ../ at the beginning of the path
	for (;;) {
		if (*p2 == '/')
			p2++;
		else if (*p2 == '.') {
			if (p2[1] == '/')
				p2 += 2;
			else if (p2[1] == '.') {
				if (p2[2] == '/')
					p2 += 3;
				else if (!p2[2])
					p2 += 2;
				else
					break;
			}
			else if (!p2[1])
				p2++;
			else
				break;
		} else
			break;
	}

	// normalize path but stop at query or fragment
	while (*p2 && *p2 != '?' && *p2 != '#') {
		if (*p2 == '/') {
			if (p2[1] == '.') {
				if (!strncmp(p2, "/../", 4)) {
					// go one level up
					p2 += 3;
					while (p1 > path && *--p1 != '/');
				} else if (!strcmp(p2, "/..")) {
					p2 += 3;
					while (p1 > path && *--p1 != '/');
					if (p1 > path) *p1++='/';
				} else if (!strncmp(p2, "/./", 3)) {
					p2 += 2;
				} else if (!strcmp(p2, "/.")) {
					p2 += 2;
					if (p1 > path) *p1++='/';
				} else
					*p1++ = *p2++;
			} else if (p1 == path)
				p2++; // avoid leading slash
			else if (p2[1] == '/')
				p2++; // double slash to single slash
			else
				*p1++ = *p2++;
		} else
			*p1++ = *p2++;
	}

	if (p1 != p2) {
		while (*p2)
			*p1++ = *p2++;

		*p1 = 0;
	}

	debug_printf("     %s\n", path);

	return p1 - path;
}

// create an absolute URI from a base + relative URI

//char *iri_relative_to_absolute(IRI *iri, const char *tag, const char *val, size_t len, char *dst, size_t dst_size)
const char *mget_iri_relative_to_abs(mget_iri_t *base, const char *val, size_t len, mget_buffer_t *buf)
{
	debug_printf("*url = %.*s\n", (int)len, val);

	if (*val == '/') {
		if (base) {
			char path[len + 1];

			// strlcpy or snprintf are ineffective here since they do strlen(val), which might be large
			memcpy(path, val, len);
			path[len] = 0;

			if (len >= 2 && val[1] == '/') {
				char *p;

				// absolute URI without scheme: //authority/path...
				if ((p = strchr(path + 2, '/')))
					_normalize_path(p + 1);

				mget_buffer_strcpy(buf, base->scheme);
				mget_buffer_strcat(buf, ":");
				mget_buffer_strcat(buf, path);
				debug_printf("*1 %s\n", buf->data);
			} else {
				// absolute path
				_normalize_path(path);

				mget_buffer_strcpy(buf, mget_iri_get_connection_part(base));
				mget_buffer_strcat(buf, "/");
				mget_buffer_strcat(buf, path);
				debug_printf("*2 %s\n", buf->data);
			}
		} else
			return NULL;
	} else {
		// see if URI begins with a scheme:
		if (memchr(val, ':', len)) {
			// absolute URI
			if (buf) {
				mget_buffer_memcpy(buf, val, len);
				debug_printf("*3 %s\n", buf->data);
			} else {
				debug_printf("*3 %s\n", val);
				return val;
			}
		} else if (base) {
			// relative path
			const char *lastsep = base->path ? strrchr(base->path, '/') : NULL;
			mget_buffer_strcpy(buf, mget_iri_get_connection_part(base));
			mget_buffer_strcat(buf, "/");

			size_t tmp_len = buf->length;

			if (lastsep)
				mget_buffer_memcat(buf, base->path, lastsep - base->path + 1);

			if (len)
				mget_buffer_memcat(buf, val, len);

			buf->length = _normalize_path(buf->data + tmp_len) + tmp_len;

			debug_printf("*4 %s %zu\n", buf->data, buf->length);
		} else if (val[len] == 0) {
			return val;
		} else
			return NULL;
	}

	return buf->data;
}

mget_iri_t *mget_iri_parse_base(mget_iri_t *base, const char *url, const char *encoding)
{
	mget_iri_t *iri;

	if (base) {
		mget_buffer_t buf;
		char sbuf[256];

		mget_buffer_init(&buf, sbuf, sizeof(sbuf));
		iri = mget_iri_parse(mget_iri_relative_to_abs(base, url, strlen(url), &buf), encoding);
		mget_buffer_deinit(&buf);
	} else {
		// no base: just check URL for being an absolute URI
		iri = mget_iri_parse(mget_iri_relative_to_abs(NULL, url, strlen(url), NULL), encoding);
	}

	return iri;
}

// RFC conform comparison as described in http://tools.ietf.org/html/rfc2616#section-3.2.3
int mget_iri_compare(mget_iri_t *iri1, mget_iri_t *iri2)
{
	int n;

//	info_printf("iri %p %p %s:%s %s:%s\n",iri1,iri2,iri1->scheme,iri1->port,iri2->scheme,iri2->port);

/*
	if (!iri1->path) {
//		if (iri2->path && strcmp(iri2->path, "/"))
		if (iri2->path)
			return -1;
	}
	else if (!iri2->path) {
//		if (iri1->path && strcmp(iri1->path, "/"))
		if (iri1->path)
			return 1;
	}
*/
	if ((n = mget_strcasecmp(iri1->path, iri2->path)))
		return n;

	if ((n = mget_strcasecmp(iri1->query, iri2->query)))
		return n;

	if (iri1->scheme != iri2->scheme)
		return iri1->scheme < iri2->scheme ? -1 : 1;

	if (iri1->port != iri2->port)
		if ((n = mget_strcmp(iri1->port, iri2->port)))
			return n;

	// host is already lowercase, no need to call strcasecmp()
	if ((n = strcmp(iri1->host, iri2->host)))
		return n;

	// if ((n = null_strcasecmp(iri1->fragment, iri2->fragment)))
	//		return n;

	return 0;
}

const char *mget_iri_escape(const char *src, mget_buffer_t *buf)
{
	const char *begin;

	for (begin = src; *src; src++) {
		if (!mget_iri_isunreserved(*src)) {
			if (begin != src)
				mget_buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			mget_buffer_printf_append2(buf, "%%%02X", (unsigned char)*src);
		}
	}

	if (begin != src)
		mget_buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

const char *mget_iri_escape_path(const char *src, mget_buffer_t *buf)
{
	const char *begin;

	for (begin = src; *src; src++) {
		if (!mget_iri_isunreserved_path(*src)) {
			if (begin != src)
				mget_buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			mget_buffer_printf_append2(buf, "%%%02X", (unsigned char)*src);
		}
	}

	if (begin != src)
		mget_buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

const char *mget_iri_escape_query(const char *src, mget_buffer_t *buf)
{
	const char *begin;

	for (begin = src; *src; src++) {
		if (!mget_iri_isunreserved(*src) && *src != '=') {
			if (begin != src)
				mget_buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			if (*src == ' ')
				mget_buffer_memcat(buf, "+", 1);
			else
				mget_buffer_printf_append2(buf, "%%%02X", (unsigned char)*src);
		}
	}

	if (begin != src)
		mget_buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

const char *mget_iri_get_escaped_host(const mget_iri_t *iri, mget_buffer_t *buf)
{
	return mget_iri_escape(iri->host, buf);
}

const char *mget_iri_get_escaped_resource(const mget_iri_t *iri, mget_buffer_t *buf)
{
	if (iri->path)
		mget_iri_escape_path(iri->path, buf);

	if (iri->query) {
		mget_buffer_memcat(buf, "?", 1);
		mget_iri_escape_query(iri->query, buf);
	}

	if (iri->fragment) {
		mget_buffer_memcat(buf, "#", 1);
		mget_iri_escape(iri->fragment, buf);
	}

	return buf->data;
}

char *mget_iri_get_path(const mget_iri_t *iri, mget_buffer_t *buf, const char *encoding)
{
	if (buf->length)
		mget_buffer_memcat(buf, "/", 1);

	if (iri->path) {
		if (mget_strcasecmp_ascii(encoding, "utf-8")) {
			char *fname;

			if ((fname = mget_utf8_to_str(iri->path, encoding))) {
				mget_buffer_strcat(buf, fname);
				xfree(fname);
			} else {
				// conversion failed, keep original string
				mget_buffer_strcat(buf, iri->path);
			}
		} else {
			mget_buffer_strcat(buf, iri->path);
		}
	}

	if ((buf->length == 0 || buf->data[buf->length - 1] == '/') && default_page)
		mget_buffer_memcat(buf, default_page, default_page_length);

	return buf->data;
}

char *mget_iri_get_query_as_filename(const mget_iri_t *iri, mget_buffer_t *buf, const char *encoding)
{
	if (iri->query) {
		const char *query;
		int allocated = 0;

		mget_buffer_memcat(buf, "?", 1);

		if (mget_strcasecmp_ascii(encoding, "utf-8")) {
			if ((query = mget_utf8_to_str(iri->query, encoding)))
				allocated = 1;
			else
				query = iri->query;
		} else
			query = iri->query;

		int slashes = 0;
		const char *src = query;

		// count slashes in query string
		while ((src = strchr(src, '/'))) {
			slashes++;
			src++;
		}

		if (slashes) {
			// escape slashes to use query as part of a filename
			const char *begin;

			for (src = begin = query; *src; src++) {
				if (*src == '/') {
					if (begin != src)
						mget_buffer_memcat(buf, begin, src - begin);
					begin = src + 1;
					mget_buffer_memcat(buf, "%2F", 3);
				}
			}

			if (begin != src)
				mget_buffer_memcat(buf, begin, src - begin);
		} else {
			mget_buffer_strcat(buf, query);
		}

		if (allocated)
			xfree(query);
	}

	return buf->data;
}

char *mget_iri_get_filename(const mget_iri_t *iri, mget_buffer_t *buf, const char *encoding)
{
	if (iri->path) {
		char *fname, *p;

		if (mget_strcasecmp_ascii(encoding, "utf-8")) {
			if ((p = strrchr(iri->path, '/'))) {
				if (!(fname = mget_utf8_to_str(p + 1, encoding)))
					mget_buffer_strcat(buf, p + 1); // conversion failed, keep original string
			} else {
				if (!(fname = mget_utf8_to_str(iri->path, encoding)))
					mget_buffer_strcat(buf, iri->path); // conversion failed, keep original string
			}

			if (fname) {
				// conversion succeeded
				mget_buffer_strcat(buf, fname);
				xfree(fname);
			}
		} else {
			if ((fname = strrchr(iri->path, '/')))
				mget_buffer_strcat(buf, fname + 1);
			else
				mget_buffer_strcat(buf, iri->path);
		}
	}

	if ((buf->length == 0 || buf->data[buf->length - 1] == '/') && default_page)
		mget_buffer_memcat(buf, default_page, default_page_length);

	return mget_iri_get_query_as_filename(iri, buf, encoding);
}

// escaping: see http://tools.ietf.org/html/rfc2396#2 following (especially 2.4.2)
/*const char *iri_escape(const char *uri)
{
	int esc = 0;
	const char *p;

	for (p = uri; *p; p++) {
		if (*p == '%') {
			if ((isxdigit(p[1]) && isxdigit(p[2])) || p[1] == '%')
				return uri; // assume that URI is already escaped
			esc++;
		} else if ()
	}
}
*/

void mget_iri_set_defaultpage(const char *page)
{
	default_page = page;
	default_page_length = default_page ? strlen(default_page) : 0;
}

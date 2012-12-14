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
 * IRI/URI routines
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
#include <iconv.h>
#include <idna.h>

#include "xalloc.h"
#include "utils.h"
#include "log.h"
#include "utf8.h"
#include "iri.h"

static const char
	*default_page = "index.html";
static size_t
	default_page_length = 10;

const char
	* const iri_schemes[] = { "http", "https", NULL },
	* const iri_ports[]   = { "80",   "443" };

#define IRI_CTYPE_GENDELIM (1<<0)
#define _iri_isgendelim(c) (iri_ctype[(unsigned char)(c)]&IRI_CTYPE_GENDELIM)

#define IRI_CTYPE_SUBDELIM (1<<0)
#define _iri_issubdelim(c) (iri_ctype[(unsigned char)(c)]&IRI_CTYPE_SUBDELIM)

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
		['\\'] = IRI_CTYPE_SUBDELIM,
		['\''] = IRI_CTYPE_SUBDELIM,
		['('] = IRI_CTYPE_SUBDELIM,
		[')'] = IRI_CTYPE_SUBDELIM,
		['*'] = IRI_CTYPE_SUBDELIM,
		['+'] = IRI_CTYPE_SUBDELIM,
		[','] = IRI_CTYPE_SUBDELIM,
		[';'] = IRI_CTYPE_SUBDELIM,
		['='] = IRI_CTYPE_SUBDELIM
	};

int iri_isgendelim(char c)
{
	// return strchr(":/?#[]@",c)!=NULL;
	return _iri_isgendelim(c);
}

int iri_issubdelim(char c)
{
	// return strchr("!$&\'()*+,;=",c)!=NULL;
	return _iri_issubdelim(c);
}

int iri_isreserved(char c)
{
	return iri_isgendelim(c) || iri_issubdelim(c);
}

int iri_isunreserved(char c)
{
	return c > 32 && c < 127 && (isalnum(c) || strchr("-._~", c) != NULL);
}

int iri_isunreserved_path(char c)
{
	return c > 32 && c < 127 && (isalnum(c) || strchr("/-._~", c) != NULL);
}

void iri_free(IRI **iri)
{
	if (iri && *iri) {
		if ((*iri)->host_allocated)
			xfree((*iri)->host);
		xfree((*iri)->connection_part);
		xfree(*iri);
	}
}

static unsigned char CONST _unhex(unsigned char c)
{
	return c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10);
}

// return 1: unescape occurred, string changed
static int _unescape(unsigned char *src)
{
	int ret = 0;
	unsigned char *dst = src;

	while (*src) {
		if (*src == '%') {
			if (isxdigit(src[1]) && isxdigit(src[2])) {
				*dst++ = (_unhex(src[1]) << 4) | _unhex(src[2]);
				src += 3;
				ret = 1;
				continue;
			}
		}

		*dst++ = *src++;
	}
	*dst = 0;

	return ret;
}

// URIs are assumed to be unescaped at this point

static IRI *iri_parse(const char *s_uri)
{
	IRI *iri;
	const char *default_port = NULL;
	char *p, *s, *authority, c;
	size_t slen, it;

	if (!s_uri)
		return NULL;

	/*
		URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
		hier-part   = "//" authority path-abempty / path-absolute / path-rootless / path-empty
		scheme      =  ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	 */
	while (isspace(*s_uri)) s_uri++;
	if (!*s_uri) return NULL;

	// just use one block of memory for all parsed URI parts
	slen = strlen(s_uri);
	iri = xmalloc(sizeof(IRI) + slen * 2 + 2);
	memset(iri, 0, sizeof(IRI));
	strcpy(((char *)iri) + sizeof(IRI), s_uri);
	iri->uri = ((char *)iri) + sizeof(IRI);
	s = ((char *)iri) + sizeof(IRI) + slen + 1;
	strcpy(s, s_uri);

	p = s;
	while (*s && !_iri_isgendelim(*s))
		s++;

	if (*s == ':' && s[1]=='/') {
		// found a scheme
		*s++ = 0;

		// find the scheme in our static list of supported schemes
		// for later comparisons we compare pointers (avoiding strcasecmnp())
		iri->scheme = p;
		for (it = 0; iri_schemes[it]; it++) {
			if (!strcasecmp(iri_schemes[it], p)) {
				iri->scheme = iri_schemes[it];
				default_port = iri_ports[it];
				break;
			}
		}

		if (iri->scheme == p) {
			// convert scheme to lowercase
			for (; *p; p++)
				if (isupper(*p))
					*p = tolower(*p);
		}

	} else {
		iri->scheme = IRI_SCHEME_DEFAULT;
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
		while (*s)
			s++;
	}

	if (*s) {
		log_printf("unparsed rest '%s'\n", s);
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
				while (*s) s++;
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
/*
		for (p = (char *)iri->host; *p; p++)
			if (*p >= 'A' && *p <= 'Z') // isupper() also returns true for chars > 0x7f, the test is not EBCDIC compatible ;-)
				*p = tolower(*p);
*/
 	}

	// now unescape all components (not interested in display, userinfo, password
	if (iri->host)
		_unescape((unsigned char *)iri->host);
	else {
		if (iri->scheme == IRI_SCHEME_HTTP || iri->scheme == IRI_SCHEME_HTTPS) {
			err_printf(_("Missing host/domain in URI '%s'\n"), iri->uri);
			iri_free(&iri);
			return NULL;
		}
	}
	if (iri->path)
		_unescape((unsigned char *)iri->path);
	if (iri->query)
		_unescape((unsigned char *)iri->query);
	if (iri->fragment)
		_unescape((unsigned char *)iri->fragment);

//	info_printf("%s: path '%s'\n", iri->uri, iri->path);

	return iri;
}

IRI *iri_parse_encoding(const char *uri, const char *encoding)
{
	IRI *iri = iri_parse(uri);

	if (iri) {
		const char *host_utf = str_to_utf8(iri->host, encoding);

		if (host_utf) {
			char *host_asc = NULL;
			int rc;

			if ((rc = idna_to_ascii_8z(host_utf, &host_asc, IDNA_USE_STD3_ASCII_RULES)) == IDNA_SUCCESS) {
				// log_printf("toASCII '%s' -> '%s'\n", host_utf, host_asc);
				iri->host = host_asc;
				iri->host_allocated = 1;
			} else
				err_printf(_("toASCII failed (%d): %s\n"), rc, idna_strerror(rc));

			xfree(host_utf);
		}

		if (iri->host) {
			char *p;

			for (p = (char *)iri->host; *p; p++)
				if (*p >= 'A' && *p <= 'Z') // isupper() also returns true for chars > 0x7f, the test is not EBCDIC compatible ;-)
					*p = tolower(*p);
		}
	}

	return iri;
}

static char *_iri_build_connection_part(IRI *iri)
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

const char *iri_get_connection_part(IRI *iri)
{
	if (iri) {
		if (!iri->connection_part)
			iri->connection_part = _iri_build_connection_part(iri);

		return iri->connection_part;
	}

	return NULL;
}

// normalize /../ and remove /./

static size_t NONNULL_ALL _normalize_path(char *path)
{
	char *p1 = path, *p2 = path;

	log_printf("path %s ->\n", path);

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

	log_printf("     %s\n", path);

	return p1 - path;
}

// create an absolute URI from a base + relative URI

//char *iri_relative_to_absolute(IRI *iri, const char *tag, const char *val, size_t len, char *dst, size_t dst_size)
const char *iri_relative_to_absolute(IRI *base, const char *val, size_t len, buffer_t *buf)
{
	log_printf("*url = %.*s\n", (int)len, val);

	if (*val == '/') {
		if (base) {
			char path[len + 1];

			strlcpy(path, val, len + 1);

			if (len >= 2 && val[1] == '/') {
				char *p;

				// absolute URI without scheme: //authority/path...
				if ((p = strchr(path + 2, '/')))
					_normalize_path(p + 1);

				buffer_strcpy(buf, base->scheme);
				buffer_strcat(buf, ":");
				buffer_strcat(buf, path);
				log_printf("*1 %s\n", buf->data);
			} else {
				// absolute path
				_normalize_path(path);

				buffer_strcpy(buf, iri_get_connection_part(base));
				buffer_strcat(buf, "/");
				buffer_strcat(buf, path);
				log_printf("*2 %s\n", buf->data);
			}
		} else
			return NULL;
	} else {
		// see if URI begins with a scheme:
		if (memchr(val, ':', len)) {
			// absolute URI
			if (buf) {
				buffer_memcpy(buf, val, len);
				log_printf("*3 %s\n", buf->data);
			} else {
				log_printf("*3 %s\n", val);
				return val;
			}
		} else if (base) {
			// relative path
			const char *lastsep = base->path ? strrchr(base->path, '/') : NULL;
			buffer_strcpy(buf, iri_get_connection_part(base));
			buffer_strcat(buf, "/");

			size_t tmp_len = buf->length;

			if (lastsep)
				buffer_memcat(buf, base->path, lastsep - base->path + 1);

			if (len)
				buffer_memcat(buf, val, len);

			buf->length = _normalize_path(buf->data + tmp_len) + tmp_len;

			log_printf("*4 %s %zu\n", buf->data, buf->length);
		} else if (val[len] == 0)
			return val;
		else
			return NULL;
	}

	return buf->data;
}

// RFC conform comparison as described in http://tools.ietf.org/html/rfc2616#section-3.2.3
int iri_compare(IRI *iri1, IRI *iri2)
{
	int n;

//	info_printf("iri %p %p %s:%s %s:%s\n",iri1,iri2,iri1->scheme,iri1->port,iri2->scheme,iri2->port);

	if (iri1->scheme != iri2->scheme)
		return iri1->scheme < iri2->scheme ? -1 : 1;

	if (iri1->port != iri2->port) {
		if ((n = null_strcmp(iri1->port, iri2->port)))
			return n;
	}

	// host is already lowercase, no need to call strcasecmp()
	if ((n = strcmp(iri1->host, iri2->host)))
		return n;

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
	else if ((n = strcasecmp(iri1->path, iri2->path)))
		return n;

	if ((n = null_strcasecmp(iri1->query, iri2->query)))
		return n;

	// if ((n = null_strcasecmp(iri1->fragment, iri2->fragment)))
	//		return n;

	return 0;
}

const char *iri_escape(const char *src, buffer_t *buf)
{
	const char *begin;

	for (begin = src; *src; src++) {
		if (!iri_isunreserved(*src)) {
			if (begin != src)
				buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			buffer_printf_append2(buf, "%%%02x", (unsigned char)*src);
		}
	}

	if (begin != src)
		buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

const char *iri_escape_path(const char *src, buffer_t *buf)
{
	const char *begin;

	for (begin = src; *src; src++) {
		if (!iri_isunreserved_path(*src)) {
			if (begin != src)
				buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			buffer_printf_append2(buf, "%%%02x", (unsigned char)*src);
		}
	}

	if (begin != src)
		buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

const char *iri_escape_query(const char *src, buffer_t *buf)
{
	const char *begin;

	for (begin = src; *src; src++) {
		if (!iri_isunreserved_path(*src) && *src != '=') {
			if (begin != src)
				buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			if (*src == ' ')
				buffer_memcat(buf, "+", 1);
			else
				buffer_printf_append2(buf, "%%%02x", (unsigned char)*src);
		}
	}

	if (begin != src)
		buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

const char *iri_get_escaped_host(const IRI *iri, buffer_t *buf)
{
	return iri_escape(iri->host, buf);
}

const char *iri_get_escaped_resource(const IRI *iri, buffer_t *buf)
{
	if (iri->path)
		iri_escape_path(iri->path, buf);

	if (iri->query) {
		buffer_memcat(buf, "?", 1);
		iri_escape_query(iri->query, buf);
	}

	if (iri->fragment) {
		buffer_memcat(buf, "#", 1);
		iri_escape(iri->fragment, buf);
	}

	return buf->data;
}

const char *iri_get_escaped_path(const IRI *iri, buffer_t *buf)
{
	if (buf->length)
		buffer_memcat(buf, "/", 1);

	if (iri->path)
		iri_escape_path(iri->path, buf);

	if ((buf->length == 0 || buf->data[buf->length - 1] == '/') && default_page)
		buffer_memcat(buf, default_page, default_page_length);

	return buf->data;
}

const char *iri_get_escaped_query(const IRI *iri, buffer_t *buf)
{
	if (iri->query) {
		buffer_memcat(buf, "?", 1);
		return iri_escape_query(iri->query, buf);
	}

	return buf->data;
}

const char *iri_get_escaped_fragment(const IRI *iri, buffer_t *buf)
{
	if (iri->fragment) {
		buffer_memcat(buf, "#", 1);
		return iri_escape(iri->fragment, buf);
	}

	return buf->data;
}


const char *iri_get_escaped_file(const IRI *iri, buffer_t *buf)
{
	if (iri->path) {
		char *fname;
		if ((fname = strrchr(iri->path, '/')))
			iri_escape_path(fname + 1, buf);
		else
			iri_escape_path(iri->path, buf);
	}

	if ((buf->length == 0 || buf->data[buf->length - 1] == '/') && default_page)
		buffer_memcat(buf, default_page, default_page_length);

	if (iri->query) {
		buffer_memcat(buf, "?", 1);
		iri_escape_query(iri->query, buf);
	}

//	if (iri->fragment) {
//		buffer_memcat(buf, "#", 1);
//		iri_escape(iri->fragment, buf);
//	}

	return buf->data;
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

void iri_set_defaultpage(const char *page)
{
	default_page = page;
	default_page_length = default_page ? strlen(default_page) : 0;
}
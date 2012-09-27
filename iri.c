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

#include <string.h>
#include <ctype.h>

#include "xalloc.h"
#include "utils.h"
#include "log.h"
#include "iri.h"

const char
	* const iri_schemes[] = { "http", "https", "ftp", NULL };

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
	return isalnum(c) || strchr("-._~", c) != NULL;
}

void iri_free(IRI **iri)
{
	if (iri && *iri) {
		xfree(*iri);
	}
}

IRI *iri_parse(const char *s_uri)
{
	IRI *iri;
	char *p, *s, *authority, c;
	int slen;

	/*
		URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
		hier-part   = "//" authority path-abempty / path-absolute / path-rootless / path-empty
		scheme      =  ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	 */
	while (isspace(*s_uri)) s_uri++;

	// just use one block of memory for all parsed URI parts
	slen = strlen(s_uri);
	iri = xmalloc(sizeof(IRI) + slen * 2 + 2);
	memset(iri, 0, sizeof(IRI));
	strcpy(((char *)iri) + sizeof(IRI), s_uri);
	strcpy(((char *)iri) + sizeof(IRI) + slen + 1, s_uri);
	iri->uri = ((char *)iri) + sizeof(IRI) + slen + 1;
	s = ((char *)iri) + sizeof(IRI);

	p = s;
	while (*s && !_iri_isgendelim(*s))
		s++;

	if (*s == ':') {
		// found a scheme
		*s++ = 0;

		if (!strcasecmp(p, IRI_SCHEME_HTTP))
			iri->scheme = IRI_SCHEME_HTTP;
		else if (!strcasecmp(p, IRI_SCHEME_HTTPS))
			iri->scheme = IRI_SCHEME_HTTPS;
		else
			iri->scheme = p;
	} else {
		iri->scheme = IRI_SCHEME_DEFAULT;
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
				iri->host = s;
				s = p + 1;
			} else {
				// something is broken
				iri->host = s;
				while (*s) s++;
			}
		} else {
			iri->host = s;
			while (*s && *s != ':')
				s++;
		}
		if (*s == ':') {
			if (s[1])
				iri->port = s + 1;
		}
		*s = 0;
	}

	return iri;
}
/*
char *iri_get_connection_part(IRI *iri, char *tag, size_t tagsize)
{
	size_t len;

	if (iri->port) {
		len = strlen(iri->scheme) + strlen(iri->host) + strlen(iri->port) + 4 + 1;
		if (len > tagsize)
			tag = xmalloc(len);

		sprintf(tag, "%s://%s:%s", iri->scheme, iri->host, iri->port);
	} else {
		len = strlen(iri->scheme) + strlen(iri->host) + 3 + 1;
		if (len > tagsize)
			tag = xmalloc(len);

		sprintf(tag, "%s://%s", iri->scheme, iri->host);
	}

	return tag;
}
*/
char *iri_get_connection_part(IRI *iri, buffer_t *buf)
{
	if (iri->port) {
		buffer_printf2(buf, "%s://%s:%s", iri->scheme, iri->host, iri->port);
	} else {
		buffer_printf2(buf, "%s://%s", iri->scheme, iri->host);
	}

	return buf->data;
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
char *iri_relative_to_absolute(IRI *base, const char *tag, const char *val, size_t len, buffer_t *buf)
{
	log_printf("*url = %.*s\n", (int)len, val);

	if (*val == '/') {
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

			buffer_strcpy(buf, tag);
			buffer_strcat(buf, "/");
			buffer_strcat(buf, path);
			log_printf("*2 %s\n", buf->data);
		}
	} else {
		// see if URI begins with a scheme:
		if (memchr(val, ':', len)) {
			// absolute URI
			buffer_memcpy(buf, val, len);
			log_printf("*3 %s\n", buf->data);
		} else {
			// relative path
			const char *lastsep = base->path ? strrchr(base->path, '/') : NULL;
			buffer_strcpy(buf, tag);
			buffer_strcat(buf, "/");

			size_t tmp_len = buf->length;

			if (lastsep)
				buffer_memcat(buf, base->path, lastsep - base->path + 1);

			if (len)
				buffer_memcat(buf, val, len);

			buf->length = _normalize_path(buf->data + tmp_len) + tmp_len;

			log_printf("*4 %s %zu\n", buf->data, buf->length);
		}
	}

	return buf->data;
}

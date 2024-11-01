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
 * URI/IRI routines
 * about encoding see http://nikitathespider.com/articles/EncodingDivination.html
 * about GET encoding see https://stackoverflow.com/questions/1549213/whats-the-correct-encoding-of-http-get-request-strings
 * RFC 3986: URI generic syntax
 *
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <string.h>
#include <errno.h>
#include "c-ctype.h"

#include <wget.h>
#include "private.h"

static char *create_safe_uri(wget_iri *iri);

/**
 * \file
 * \brief Functions to work with URIs and IRIs
 * \defgroup libwget-iri URIs/IRIs
 *
 * @{
 *
 * URI/IRI parsing and manipulation functions.
 *
 * IRIs are processed according to [RFC 3987](https://datatracker.ietf.org/doc/rfc3987/).
 * Functions that escape certain characters (such as wget_iri_escape()) work according to
 * [RFC 3986](https://datatracker.ietf.org/doc/rfc3986/).
 *
 * The \ref wget_iri_st "wget_iri" structure represents an IRI. You generate one from a string with wget_iri_parse() or
 * wget_iri_parse_base(). You can use wget_iri_clone() to generate another identical \ref wget_iri_st "wget_iri".
 *
 * You can access each of the fields of a \ref wget_iri_st "wget_iri" (such as `path`) independently, and you can use
 * the getters here to escape each of those parts, or for convenience (e.g wget_iri_get_escaped_host(),
 * wget_iri_get_escaped_resource(), etc.).
 *
 * URIs/IRIs are all internally treated in UTF-8. The parsing functions that generate a \ref wget_iri_st "wget_iri" structure
 * (wget_iri_parse() and wget_iri_parse_base()) thus convert the input string to UTF-8 before anything else.
 * These functions take an `encoding` parameter that tells which is the original encoding of that string.
 *
 * Conversely, the getters (for example, wget_iri_get_path()) can convert the output string from UTF-8
 * to an encoding of choice. The desired encoding is also specified in the `encoding` parameter.
 *
 * The `encoding` parameter, in all functions that accept it, is a string with the name of a character set
 * supported by GNU libiconv. You can find such a list elsewhere, but popular examples are "utf-8", "utf-16" or "iso-8859-1".
 */

static const char
	*default_page = "index.html";
static size_t
	default_page_length = 10;

static struct iri_scheme {
	uint16_t port;
	const char name[6];
} schemes[] = {
	[WGET_IRI_SCHEME_HTTP]  = {  80, "http"  },
	[WGET_IRI_SCHEME_HTTPS] = { 443, "https" },
};

static size_t WGET_GCC_NONNULL_ALL normalize_path(char *path);

/**
 * \param[in] scheme Scheme to get name for
 * \return Name of \p scheme (e.g. "http" or "https") or NULL is not supported
 *
 * Maps \p scheme to it's string representation.
 */
const char *wget_iri_scheme_get_name(wget_iri_scheme scheme)
{
	if ((unsigned) scheme < countof(schemes))
		return schemes[scheme].name;

	return NULL;
}

/**
 * \param[in] iri An IRI
 * \return 1 if the scheme is supported, 0 if not
 *
 * Tells whether the IRI's scheme is supported or not.
 */
bool wget_iri_supported(const wget_iri *iri)
{
	return (unsigned) iri->scheme < countof(schemes);
}


/* \cond _hide_internal_symbols */
#define IRI_CTYPE_GENDELIM (1<<0)
#define iri_isgendelim(c) (iri_ctype[(unsigned char)(c)] & IRI_CTYPE_GENDELIM)

#define IRI_CTYPE_SUBDELIM (1<<1)
#define iri_issubdelim(c) (iri_ctype[(unsigned char)(c)] & IRI_CTYPE_SUBDELIM)

#define IRI_CTYPE_UNRESERVED (1<<2)
#define iri_isunreserved(c) (iri_ctype[(unsigned char)(c)] & IRI_CTYPE_UNRESERVED)

#define iri_isscheme(c) (c_isalnum(c) || c == '+' || c == '-' || c == '.')
/* \endcond */

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
		['\''] = IRI_CTYPE_SUBDELIM,
		['('] = IRI_CTYPE_SUBDELIM,
		[')'] = IRI_CTYPE_SUBDELIM,
		['*'] = IRI_CTYPE_SUBDELIM,
		['+'] = IRI_CTYPE_SUBDELIM,
		[','] = IRI_CTYPE_SUBDELIM,
		[';'] = IRI_CTYPE_SUBDELIM,
		['='] = IRI_CTYPE_SUBDELIM,

		['0'] = IRI_CTYPE_UNRESERVED,
		['1'] = IRI_CTYPE_UNRESERVED,
		['2'] = IRI_CTYPE_UNRESERVED,
		['3'] = IRI_CTYPE_UNRESERVED,
		['4'] = IRI_CTYPE_UNRESERVED,
		['5'] = IRI_CTYPE_UNRESERVED,
		['6'] = IRI_CTYPE_UNRESERVED,
		['7'] = IRI_CTYPE_UNRESERVED,
		['8'] = IRI_CTYPE_UNRESERVED,
		['9'] = IRI_CTYPE_UNRESERVED,
		['a'] = IRI_CTYPE_UNRESERVED,
		['b'] = IRI_CTYPE_UNRESERVED,
		['c'] = IRI_CTYPE_UNRESERVED,
		['d'] = IRI_CTYPE_UNRESERVED,
		['e'] = IRI_CTYPE_UNRESERVED,
		['f'] = IRI_CTYPE_UNRESERVED,
		['g'] = IRI_CTYPE_UNRESERVED,
		['h'] = IRI_CTYPE_UNRESERVED,
		['i'] = IRI_CTYPE_UNRESERVED,
		['j'] = IRI_CTYPE_UNRESERVED,
		['k'] = IRI_CTYPE_UNRESERVED,
		['l'] = IRI_CTYPE_UNRESERVED,
		['m'] = IRI_CTYPE_UNRESERVED,
		['n'] = IRI_CTYPE_UNRESERVED,
		['o'] = IRI_CTYPE_UNRESERVED,
		['p'] = IRI_CTYPE_UNRESERVED,
		['q'] = IRI_CTYPE_UNRESERVED,
		['r'] = IRI_CTYPE_UNRESERVED,
		['s'] = IRI_CTYPE_UNRESERVED,
		['t'] = IRI_CTYPE_UNRESERVED,
		['u'] = IRI_CTYPE_UNRESERVED,
		['v'] = IRI_CTYPE_UNRESERVED,
		['w'] = IRI_CTYPE_UNRESERVED,
		['x'] = IRI_CTYPE_UNRESERVED,
		['y'] = IRI_CTYPE_UNRESERVED,
		['z'] = IRI_CTYPE_UNRESERVED,
		['A'] = IRI_CTYPE_UNRESERVED,
		['B'] = IRI_CTYPE_UNRESERVED,
		['C'] = IRI_CTYPE_UNRESERVED,
		['D'] = IRI_CTYPE_UNRESERVED,
		['E'] = IRI_CTYPE_UNRESERVED,
		['F'] = IRI_CTYPE_UNRESERVED,
		['G'] = IRI_CTYPE_UNRESERVED,
		['H'] = IRI_CTYPE_UNRESERVED,
		['I'] = IRI_CTYPE_UNRESERVED,
		['J'] = IRI_CTYPE_UNRESERVED,
		['K'] = IRI_CTYPE_UNRESERVED,
		['L'] = IRI_CTYPE_UNRESERVED,
		['M'] = IRI_CTYPE_UNRESERVED,
		['N'] = IRI_CTYPE_UNRESERVED,
		['O'] = IRI_CTYPE_UNRESERVED,
		['P'] = IRI_CTYPE_UNRESERVED,
		['Q'] = IRI_CTYPE_UNRESERVED,
		['R'] = IRI_CTYPE_UNRESERVED,
		['S'] = IRI_CTYPE_UNRESERVED,
		['T'] = IRI_CTYPE_UNRESERVED,
		['U'] = IRI_CTYPE_UNRESERVED,
		['V'] = IRI_CTYPE_UNRESERVED,
		['W'] = IRI_CTYPE_UNRESERVED,
		['X'] = IRI_CTYPE_UNRESERVED,
		['Y'] = IRI_CTYPE_UNRESERVED,
		['Z'] = IRI_CTYPE_UNRESERVED,
		['-'] = IRI_CTYPE_UNRESERVED,
		['.'] = IRI_CTYPE_UNRESERVED,
		['_'] = IRI_CTYPE_UNRESERVED,
		['~'] = IRI_CTYPE_UNRESERVED
	};

/**
 * \param[in] c A character
 * \return 1 if \p c is a generic delimiter, 0 if not
 *
 * Tests whether \p c is a generic delimiter (gen-delim),
 * according to [RFC 3986, sect. 2.2](https://tools.ietf.org/html/rfc3986#section-2.2).
 */
bool wget_iri_isgendelim(char c)
{
	// return strchr(":/?#[]@",c)!=NULL;
	return iri_isgendelim(c);
}

/**
 * \param[in] c A character
 * \return 1 if \p c is a subcomponent delimiter, 0 if not
 *
 * Tests whether \p c is a subcomponent delimiter (sub-delim)
 * according to [RFC 3986, sect. 2.2](https://tools.ietf.org/html/rfc3986#section-2.2).
 */
bool wget_iri_issubdelim(char c)
{
	// return strchr("!$&\'()*+,;=",c)!=NULL;
	return iri_issubdelim(c);
}

/**
 * \param[in] c A character
 * \return 1 if \p c is a reserved character, 0 if not
 *
 * Tests whether \p c is a reserved character.
 *
 * According to [RFC 3986, sect. 2.2](https://tools.ietf.org/html/rfc3986#section-2.2),
 * the set of reserved characters is formed
 * by the generic delimiters (gen-delims, wget_iri_isgendelim()) and the
 * subcomponent delimiters (sub-delims, wget_iri_is_subdelim()).
 *
 * This function is thus equivalent to:
 *
 *     return wget_iri_isgendelim(c) || wget_iri_issubdelim(c);
 *
 */
bool wget_iri_isreserved(char c)
{
	return wget_iri_isgendelim(c) || wget_iri_issubdelim(c);
}

/**
 * \param[in] c A character
 * \return 1 if \p c is an unreserved character, 0 if not
 *
 * Tests whether \p c is an unreserved character.
 */
bool wget_iri_isunreserved(char c)
{
	return iri_isunreserved(c);
}

static unsigned char WGET_GCC_CONST unhex(unsigned char c)
{
	return c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10);
}

static char *iri_unescape_inline(char *src, int ctype)
{
	char *ret = NULL;
	unsigned char *s = (unsigned char *)src; // just a helper to avoid casting a lot
	unsigned char *d = s;

	while (*s) {
		if (*s == '%') {
			if (c_isxdigit(s[1]) && c_isxdigit(s[2])) {
				unsigned char c = (unsigned char) (unhex(s[1]) << 4) | unhex(s[2]);
				if (!ctype || (!(iri_ctype[(unsigned char)(c)] & ctype) && c != '%')) {
					*d++ = c;
					s += 3;
					ret = src;
					continue;
				}
			}
		} else if (*s == '#') {
			uint32_t value = 0;

			if (s[1] == 'x') {
				unsigned char *p = s + 2;
				while (c_isxdigit(*p)) {
					value = ((value & 0x0FFFFFFF) << 4) | unhex(*p);
					p++;
				}
				if (*p == ';') {
					if (value > 0 && value < 128) {
						*d++ = (unsigned char) value;
						s = p + 1;
						continue;
					}
					// else: we have to convert the unicode value to whatever encoding the URL is in (likely UTF-8)
					// this cannot be done inline since the URL's length may increase
				}
			} else {
				unsigned char *p = s + 1;
				while (c_isdigit(*p) && value <= 0x10FFFF) { // max. Unicode value
					value = value * 10 + (*p - '0');
					p++;
				}
				if (*p == ';') {
					if (value > 0 && value < 128) {
						*d++ = (unsigned char) value;
						s = p + 1;
						continue;
					}
					// else: we have to convert the unicode value to whatever encoding the URL is in (likely UTF-8)
					// this cannot be done inline since the URL's length may increase
				}
			}
		} else if (*s == '\r' || *s == '\n') {
			// Ignore / remove CR and LF from URLs. See https://gitlab.com/gnuwget/wget2/-/issues/522
			s++;
			continue;
		}

		*d++ = *s++;
	}
	*d = 0;

	return ret;
}

/**
 * \param[in] src A string
 * \return A pointer to \p src, after the transformation is done
 *
 * Unescape a string. All the percent-encoded characters (`%XX`) are converted
 * back to their original form.
 *
 * **The transformation is done inline**, so `src` will be modified after this function returns.
 * If no percent-encoded characters are found, the string is left untouched.
 */
char *wget_iri_unescape_inline(char *src)
{
	return iri_unescape_inline(src, 0);
}

/**
 * \param[in] src A string
 * \return A pointer to \p src, after the transformation is done
 *
 * Unescape a string except escaped generic delimiters (and escaped '%'.
 * The percent-encoded characters (`%XX`) are converted back to their original form.
 *
 * This variant of unescaping is helpful before an URL is being parsed, so that
 * the parser recognizes e.g. 'http%3A//' as relative URL (path) and not as a scheme.
 *
 * **The transformation is done inline**, so `src` will be modified after this function returns.
 * If no characters were unescaped, the string is left untouched.
 */
char *wget_iri_unescape_url_inline(char *src)
{
	return iri_unescape_inline(src, IRI_CTYPE_GENDELIM);
}

/**
 * \param[in] iri An IRI
 *
 * Free the heap-allocated content of the provided IRI, but leave the rest
 * of the fields.
 *
 * This function frees the following fields of \ref wget_iri_st "wget_iri":
 *
 *  - `host`
 *  - `path`
 *  - `query`
 *  - `fragment`
 *  - `connection_part`
 */
void wget_iri_free_content(wget_iri *iri)
{
	if (iri) {
		if (iri->userinfo)
			xfree(iri->safe_uri);
		else
			iri->safe_uri = NULL;
		if (iri->uri_allocated)
			xfree(iri->uri);
		if (iri->host_allocated)
			xfree(iri->host);
		if (iri->path_allocated)
			xfree(iri->path);
		if (iri->query_allocated)
			xfree(iri->query);
		if (iri->fragment_allocated)
			xfree(iri->fragment);
		xfree(iri->connection_part);
	}
}

/**
 * \param[in] iri A pointer to a pointer to an IRI (a \ref wget_iri_st "wget_iri")
 *
 * Destroy a \ref wget_iri_st "wget_iri" structure.
 *
 * The provided pointer is set to NULL.
 */
void wget_iri_free(wget_iri **iri)
{
	if (iri && *iri) {
		wget_iri_free_content(*iri);
		xfree(*iri);
	}
}

// URIs are assumed to be unescaped at this point

/**
 * \param[in] url A URL/IRI
 * \param[in] encoding Original encoding of \p url
 * \return A libwget IRI (`wget_iri`)
 *
 * The host, path, query and fragment parts will be converted to UTF-8 from
 * the encoding given in the parameter \p encoding. GNU libiconv is used
 * to perform the conversion, so this value should be the name of a valid character set
 * supported by that library, such as "utf-8" or "iso-8859-1".
 */
wget_iri *wget_iri_parse(const char *url, const char *encoding)
{
	wget_iri *iri;
	char *p, *s, *authority, c;
	size_t slen, extra;
	int have_scheme;

	if (!url)
		return NULL;

	/*
		URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
		hier-part   = "//" authority path-abempty / path-absolute / path-rootless / path-empty
		scheme      =  ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	 */
	while (c_isspace(*url)) url++;
	if (!*url) return NULL;
/*
	// first unescape, than convert to UTF-8
	if (strchr(url, '%')) {
		char *unesc_url = wget_strdup(url);

		wget_percent_unescape(unesc_url);

		if (wget_str_needs_encoding(unesc_url)) {
			if ((url = wget_str_to_utf8(unesc_url, encoding)))
				xfree(unesc_url);
			else
				url = unesc_url; // on error, use what we have
		} else
			url = unesc_url;

		url_allocated = 1;
	} else {
		url_allocated = 0;

		if (wget_str_needs_encoding(url)) {
			if ((s = wget_str_to_utf8(url, encoding))) {
				url = s;
				url_allocated = 1;
			}
		}
	}
*/

	if (c_isalpha(*url)) {
		const char *x;
		have_scheme = 1;

		for (x = url; *x && iri_isscheme(*x); x++)
			;

		if (*x != ':' || c_isdigit(x[1]))
			have_scheme = 0; // not a scheme
	} else
		have_scheme = 0;

	// just use one block of memory for all parsed URI parts
	slen = strlen(url);
	extra = have_scheme ? 0 : sizeof("http://") - 1; // extra space for http://

	iri = wget_malloc(sizeof(wget_iri) + (slen + extra + 1) * 2);
	if (!iri)
		return NULL;

	memset(iri, 0, sizeof(wget_iri));

	if (have_scheme) {
		iri->msize = slen + 1;
		iri->uri = memcpy(iri + 1, url, iri->msize);
		p = s = memcpy((char *)iri->uri + iri->msize, url, iri->msize);
		s = strchr(s, ':'); // we know there is a :
		*s++ = 0;

		// p points to scheme
		wget_iri_unescape_inline(p); // percent unescape
		wget_strtolower(p); // convert to lowercase

		bool found = false; // assume the scheme is unsupported

		// find the scheme in our static list of supported schemes
		// for later comparisons we compare pointers (avoiding strcasecmp())
		for (unsigned it = 0; it < countof(schemes); it++) {
			if (!strcmp(schemes[it].name, p)) {
				iri->scheme = it;
				iri->port = schemes[it].port;
				found = true;
				break;
			}
		}

		if (!found) {
			debug_printf("Unsupported scheme in '%s'\n", url);
			wget_iri_free(&iri);
			return NULL;
		}
	} else {
		// add http:// scheme to url
		iri->uri = memcpy(iri + 1, "http://", extra);
		memcpy((char *)iri->uri + extra, url, slen + 1);
		iri->msize = extra + slen + 1;
		s = memcpy((char *)iri->uri + iri->msize, iri->uri, iri->msize);
		s[extra - 3] = 0;
		s += extra;

		iri->scheme = WGET_IRI_SCHEME_HTTP;
		iri->port = schemes[WGET_IRI_SCHEME_HTTP].port;
	}

//	if (url_allocated)
//		xfree(url);

	// this is true for http, https, ftp, file (accept any number of /, like most browsers)
	while (*s == '/')
		s++;

	// authority
	authority = s;
	while (*s && *s != '/' && *s != '?' && *s != '#')
		s++;
	c = *s;
	if (c) *s++ = 0;
	wget_iri_unescape_inline(authority);

	// left over: [path][?query][#fragment]
	if (c == '/') {
		iri->path = s;
		while (*s && *s != '?' && *s != '#')
			s++;
		c = *s;
		if (c) *s++ = 0;
		wget_iri_unescape_inline((char *)iri->path);
		normalize_path((char *)iri->path);
	}

	if (c == '?') {
		iri->query = s;
		while (*s && *s != '#') {
			if (*s == '+')
				*s = ' ';
			s++;
		}
		c = *s;
		if (c) *s++ = 0;
		/* do not unescape query else we get ambiguity for chars like &, =, +, ... */
	}

	if (c == '#') {
		iri->fragment = s;
		s += strlen(s);
		wget_iri_unescape_inline((char *)iri->fragment);
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
			if ((s = strchr(s, ':'))) {
				*s = 0;
				iri->password = s + 1;
			}
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
			if (c_isdigit(s[1])) {
				unsigned long port = strtoul(s + 1, NULL, 10);
				if (port == 0 || port > 65535) {
					error_printf(_("Port number must be in the range 1..65535\n"));
					wget_iri_free(&iri);
					return NULL;
				}
				iri->port = (uint16_t) port;
				iri->port_given = true;
			}
		}
		*s = 0;
	}

	// now unescape all components (not interested in display, userinfo, password right now)

	if (iri->host) {
		wget_strtolower((char *)iri->host);
		if (wget_str_needs_encoding(iri->host)) {
			if ((s = wget_str_to_utf8(iri->host, encoding))) {
				iri->host = s;
				iri->host_allocated = true;
			}
		}
		if ((p = (char *)wget_str_to_ascii(iri->host)) != iri->host) {
			if (iri->host_allocated)
				xfree(iri->host);
			iri->host = p;
			iri->host_allocated = true;
		}

		// Finally, if the host is a literal IPv4 or IPv6 address, mark it as so
		if (wget_ip_is_family(iri->host, WGET_NET_FAMILY_IPV4) || wget_ip_is_family(iri->host, WGET_NET_FAMILY_IPV6))
			iri->is_ip_address = true;
	}

	if (!iri->host) {
		error_printf(_("Missing host/domain in URI '%s'\n"), iri->uri);
		wget_iri_free(&iri);
		return NULL;
	}

	if (iri->path && wget_str_needs_encoding(iri->path)) {
		if ((s = wget_str_to_utf8(iri->path, encoding))) {
			iri->path = s;
			iri->path_allocated = true;
		}
	}

	if (iri->query && wget_str_needs_encoding(iri->query)) {
		if ((s = wget_str_to_utf8(iri->query, encoding))) {
			iri->query = s;
			iri->query_allocated = true;
		}
	}

	if (iri->fragment && wget_str_needs_encoding(iri->fragment)) {
		if ((s = wget_str_to_utf8(iri->fragment, encoding))) {
			iri->fragment = s;
			iri->fragment_allocated = true;
		}
	}

	if (iri->userinfo) {
		iri->safe_uri = create_safe_uri(iri);
	} else {
		iri->safe_uri = iri->uri;
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

/**
 * \param[in] iri An IRI
 * \return A new IRI, with the exact same contents as the provided one.
 *
 * Clone the provided IRI.
 */
wget_iri *wget_iri_clone(const wget_iri *iri)
{
	if (!iri || !iri->uri)
		return NULL;

	size_t slen = strlen(iri->uri);
	wget_iri *clone = wget_malloc(sizeof(wget_iri) + (slen + 1) + iri->msize);

	if (!clone)
		return NULL;

	memcpy(clone, iri, sizeof(wget_iri));
	clone->uri = memcpy(clone + 1, iri->uri, (slen + 1) + iri->msize);
	clone->uri_allocated = 0;

	if (iri->userinfo)
		clone->safe_uri = wget_strdup(iri->safe_uri);
	else
		clone->safe_uri = clone->uri;

	clone->connection_part = wget_strdup(iri->connection_part);

	// adjust pointers
	if (iri->host_allocated)
		clone->host = wget_strdup(iri->host);
	else
		clone->host = iri->host ? (char *)clone + (size_t) (iri->host - (const char *)iri) : NULL;

	clone->display = iri->display ? (char *)clone + (size_t) (iri->display - (const char *)iri): NULL;
	// not adjust scheme, it is a pointer to a static string
	clone->userinfo = iri->userinfo ? (char *)clone + (size_t) (iri->userinfo - (const char *)iri): NULL;
	clone->password = iri->password ? (char *)clone + (size_t) (iri->password - (const char *)iri): NULL;

	if (iri->path_allocated)
		clone->path = wget_strdup(iri->path);
	else
		clone->path = iri->path ? (char *)clone + (size_t) (iri->path - (const char *)iri): NULL;

	if (iri->query_allocated)
		clone->query = wget_strdup(iri->query);
	else
		clone->query = iri->query ? (char *)clone + (size_t) (iri->query - (const char *)iri): NULL;

	if (iri->fragment_allocated)
		clone->fragment = wget_strdup(iri->fragment);
	else
		clone->fragment = iri->fragment ? (char *)clone + (size_t) (iri->fragment - (const char *)iri): NULL;

	return clone;
}

/**
 * \param[in] iri An IRI
 * \param[in] buf A buffer, where the resulting string will be put
 * \return The contents of the buffer \p buf
 *
 * Append the connection part of the IRI \p iri to \p buf.
 *
 * The connection part is formed by the scheme, the hostname, and optionally the port. For example:
 *
 *     https://localhost:8080
 *     https://www.example.com
 *
 * It may be of the form `https://example.com:8080` if the port was provided when creating the IRI
 * or of the form `https://example.com` otherwise.
 */
const char *wget_iri_get_connection_part(const wget_iri *iri, wget_buffer *buf)
{
	if (iri) {
		if (wget_ip_is_family(iri->host, WGET_NET_FAMILY_IPV6))
			wget_buffer_printf_append(buf, "%s://[%s]", schemes[iri->scheme].name, iri->host);
		else
			wget_buffer_printf_append(buf, "%s://%s", schemes[iri->scheme].name, iri->host);

		if (iri->port_given)
			wget_buffer_printf_append(buf, ":%hu", iri->port);
	}

	return buf->data;
}

// normalize /../ and remove /./

static size_t WGET_GCC_NONNULL_ALL normalize_path(char *path)
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
	} else {
		p1 += strlen(p1);
	}

	debug_printf("     %s\n", path);

	return p1 - path;
}

// create an absolute URI from a base + relative URI

//char *iri_relative_to_absolute(IRI *iri, const char *tag, const char *val, size_t len, char *dst, size_t dst_size)
/**
 * \param[in] base A base IRI
 * \param[in] val A path, or another URI
 * \param[in] len Length of the string \p val or -1
 * \param[in] buf Destination buffer, where the result will be copied.
 * \return A new URI (string) which is based on the base IRI \p base provided, or NULL in case of error.
 *
 * Calculates a new URI which is based on the provided IRI \p base.
 *
 * Taking the IRI \p base as a starting point, a new URI is created with the path \p val, which may be
 * a relative or absolute path, or even a whole URI. The result is returned as a string, and if the buffer
 * \p buf is provided, it is also placed there.
 *
 * If \p val is an absolute path (it begins with a `/`), it is normalized first. Then the provided IRI's
 * path is replaced by that new path. If it's a relative path, the file name of the \p base IRI's path
 * is replaced by that path. Finally, if \p val begins with a scheme (such as `https://`) that string is returned
 * untouched, and placed in the buffer if provided.
 *
 * If \p base is NULL, then \p val must itself be an absolute URI. Likewise, if \p buf is NULL,
 * then \p val must also be an absolute URI.
 *
 * if \p len is `-1`, the length of \p val will be the result from `strlen(val)`.
 */
const char *wget_iri_relative_to_abs(const wget_iri *base, const char *val, size_t len, wget_buffer *buf)
{
	if (len == (size_t) -1)
		len = strlen(val);

	if (*val == '/') {
		if (base) {
			char tmp[4096], *path = tmp;

			if (len >= sizeof(tmp)) {
				path = wget_malloc(len + 1);
				if (!path)
					return NULL;
			}

			// strlcpy or snprintf are ineffective here since they do strlen(val), which might be large
			wget_strscpy(path, val, len + 1);

			if (len >= 2 && val[1] == '/') {
				char *p;

				// absolute URI without scheme: //authority/path...
				if ((p = strchr(path + 2, '/')))
					normalize_path(p + 1);

				wget_buffer_strcpy(buf, schemes[base->scheme].name);
				wget_buffer_strcat(buf, ":");
				wget_buffer_strcat(buf, path);
			} else {
				// absolute path
				normalize_path(path);

				wget_buffer_reset(buf);
				wget_iri_get_connection_part(base, buf);
				wget_buffer_strcat(buf, "/");
				wget_buffer_strcat(buf, path);
			}

			if (path != tmp)
				xfree(path);
		} else {
			return NULL;
		}
	} else {
		// see if URI begins with a scheme:
		if (memchr(val, ':', len)) {
			// absolute URI
			if (buf) {
				wget_buffer_memcpy(buf, val, len);
			} else {
				return val;
			}
		} else if (base) {
			// relative path
			const char *lastsep = base->path ? strrchr(base->path, '/') : NULL;
			wget_buffer_reset(buf);
			wget_iri_get_connection_part(base, buf);
			wget_buffer_strcat(buf, "/");

			size_t tmp_len = buf->length;

			if (lastsep)
				wget_buffer_memcat(buf, base->path, lastsep - base->path + 1);

			if (len)
				wget_buffer_memcat(buf, val, len);

			buf->length = normalize_path(buf->data + tmp_len) + tmp_len;
		} else if (val[len] == 0) {
			return val;
		} else {
			return NULL;
		}
	}

	return likely(buf) ? buf->data : NULL;
}

/**
 * \param[in] base The base IRI
 * \param[in] url A relative/absolute path (or a URI) to be appended to \p base
 * \param[in] encoding The encoding of \p url (e.g. "utf-8" or "iso-8859-1")
 * \return A new IRI
 *
 * Generate a new IRI by using the provided IRI \p base as a base and the path \p url.
 *
 * This is equivalent to:
 *
 *     wget_iri *iri = wget_iri_parse(wget_iri_relative_to_abs(base, url, strlen(url), NULL), encoding);
 *     return iri;
 *
 * As such, \p url can be a relative or absolute path, or another URI.
 *
 * If \p base is NULL, then the parameter \p url must itself be an absolute URI.
 */
wget_iri *wget_iri_parse_base(const wget_iri *base, const char *url, const char *encoding)
{
	wget_iri *iri;

	if (base) {
		wget_buffer buf;
		char sbuf[256];

		wget_buffer_init(&buf, sbuf, sizeof(sbuf));
		iri = wget_iri_parse(wget_iri_relative_to_abs(base, url, (size_t) -1, &buf), encoding);
		wget_buffer_deinit(&buf);
	} else {
		// no base: just check URL for being an absolute URI
		iri = wget_iri_parse(wget_iri_relative_to_abs(NULL, url, (size_t) -1, NULL), encoding);
	}

	return iri;
}

// RFC conform comparison as described in https://tools.ietf.org/html/rfc2616#section-3.2.3
/**
 * \param[in] iri1 An IRI
 * \param[in] iri2 Another IRI
 * \return 0 if both IRIs are equal according to RFC 2616 or a non-zero value otherwise
 *
 * Compare two IRIs.
 *
 * Comparison is performed according to [RFC 2616, sect. 3.2.3](https://tools.ietf.org/html/rfc2616#section-3.2.3).
 *
 * This function uses wget_strcasecmp() to compare the various parts of the IRIs so a non-zero negative return value
 * indicates that \p iri1 is less than \p iri2, whereas a positive value indicates \p iri1 is greater than \p iri2.
 */
int wget_iri_compare(const wget_iri *iri1, const wget_iri *iri2)
{
	int n;

	if (!iri1) {
		if (!iri2)
			return 0;
		else
			return -1;
	} else if (!iri2)
		return 1;

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
	if ((n = wget_strcasecmp(iri1->path, iri2->path)))
		return n;

	if ((n = wget_strcasecmp(iri1->query, iri2->query)))
		return n;

	if (iri1->scheme != iri2->scheme)
		return iri1->scheme < iri2->scheme ? -1 : 1;

	if ((n = iri1->port - iri2->port))
		return n;

	// host is already lowercase, no need to call strcasecmp()
	if ((n = strcmp(iri1->host, iri2->host)))
		return n;

	// if ((n = wget_strcasecmp(iri1->fragment, iri2->fragment)))
	//		return n;

	return 0;
}

/**
 * \param[in] src A string, whose reserved characters are to be percent-encoded
 * \param[in] buf A buffer where the result will be copied.
 * \return The contents of the buffer \p buf after \p src has been encoded.
 *
 * Escapes (using percent-encoding) all the reserved characters in the string \p src.
 *
 * If \p src is NULL, the contents of the buffer \p buf are returned. \p buf cannot be NULL.
 */
const char *wget_iri_escape(const char *src, wget_buffer *buf)
{
	const char *begin;

	if (!src)
		return buf->data;

	for (begin = src; *src; src++) {
		if (!iri_isunreserved(*src)) {
			if (begin != src)
				wget_buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			wget_buffer_printf_append(buf, "%%%02X", (unsigned char)*src);
		}
	}

	if (begin != src)
		wget_buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

/**
 * \param[in] src A string, whose reserved characters are to be percent-encoded
 * \param[in] buf A buffer where the result will be copied.
 * \return The contents of the buffer \p buf after \p src has been encoded
 * as described in https://datatracker.ietf.org/doc/html/rfc7230#section-5.3.1.
 *
 * Escapes the path part of the URI suitable for GET/POST requests (origin-form).
 *   origin-form    = absolute-path [ "?" query ]
 *   path-absolute = "/" [ segment-nz *( "/" segment ) ]
 *   segment-nz    = 1*pchar
 *   segment       = *pchar
 *   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
 */
const char *wget_iri_escape_path(const char *src, wget_buffer *buf)
{
	const char *begin;

	for (begin = src; *src; src++) {
		if (!(iri_isunreserved(*src) || iri_issubdelim(*src) || *src == '/' || *src == ':' || *src == '@')) {
			if (begin != src)
				wget_buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			wget_buffer_printf_append(buf, "%%%02X", (unsigned char)*src);
		}
	}

	if (begin != src)
		wget_buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

/**
 * \param[in] src A string, whose reserved characters are to be percent-encoded
 * \param[in] buf A buffer where the result will be copied.
 * \return The contents of the buffer \p buf after \p src has been encoded.
 *
 * Escapes (using percent-encoding) all the reserved characters in the string \p src
 * (just like wget_iri_escape()), but **excluding the equal sign `=` and the ampersand `&`**.
 * This function is thus ideally suited for query parts of URIs.
 */
const char *wget_iri_escape_query(const char *src, wget_buffer *buf)
{
	const char *begin;

	for (begin = src; *src; src++) {
		if (!iri_isunreserved(*src) && *src != '=' && *src != '&') {
			if (begin != src)
				wget_buffer_memcat(buf, begin, src - begin);
			begin = src + 1;
			if (*src == ' ')
				wget_buffer_memcat(buf, "+", 1);
			else
				wget_buffer_printf_append(buf, "%%%02X", (unsigned char)*src);
		}
	}

	if (begin != src)
		wget_buffer_memcat(buf, begin, src - begin);

	return buf->data;
}

/**
 * \param[in] iri An IRI
 * \param[in] buf A buffer, where the resulting string will be put
 * \return The contents of the buffer \p buf
 *
 * Return the host part of the provided IRI. It is placed in the buffer \p buf
 * and also returned as a `const char *`.
 *
 * The host is escaped using wget_iri_escape().
 */
const char *wget_iri_get_escaped_host(const wget_iri *iri, wget_buffer *buf)
{
	return wget_iri_escape(iri->host, buf);
}

/**
 * \param[in] iri An IRI
 * \param[in] buf A buffer, where the resulting string will be put
 * \return The contents of the buffer \p buf
 *
 * Return the resource string, suitable for use in HTTP requests.
 * Details:
 *   https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.1
 *   https://datatracker.ietf.org/doc/html/rfc7230#section-2.7
 *   https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
 *
 * The resource string is comprised of the path, plus the query part, if present. Example:
 *
 *     /foo/bar/?param_1=one&param_2=two
 *
 * Both the path and the query are escaped using wget_iri_escape_path() and
 * wget_iri_escape_query(), respectively.
 *
 * The resulting string is placed in the buffer \p buf and also returned as a `const char *`.
 */
const char *wget_iri_get_escaped_resource(const wget_iri *iri, wget_buffer *buf)
{
	if (iri->path)
		wget_iri_escape_path(iri->path, buf);

	// Do not actually escape the query field. This part of the URL *MAY*
	// contain reserved characters which should be passed on as-is and without
	// escaping them. This is according to the rules laid out in RFC 2616 and
	// RFC 7230. But we have to replace spaces in any case.
	if (iri->query) {
		wget_buffer_memcat(buf, "?", 1);
		for (const char *p = iri->query; *p; p++)
			wget_buffer_memcat(buf, *p == ' ' ? "+" : p, 1);
	}

	return buf->data;
}

/**
 * \param[in] iri An IRI
 * \param[in] buf A buffer, where the resulting string will be put
 * \param[in] encoding Character set the string should be converted to
 * \return The contents of the buffer \p buf
 *
 * Get the path part of the provided IRI.
 *
 * The path is appended to \p buf. If \p buf is non-empty and does not end with
 * a path separator (`/`), then one is added before the path is appended to \p
 * buf.
 *
 * If \p encoding is provided, this function will try to convert the path (which is originally
 * in UTF-8) to that encoding.
 */

char *wget_iri_get_path(const wget_iri *iri, wget_buffer *buf, const char *encoding)
{
	if (buf->length != 0 && buf->data[buf->length - 1] != '/')
		wget_buffer_memcat(buf, "/", 1);

	if (iri->path) {
		if (wget_strcasecmp_ascii(encoding, "utf-8")) {
			char *fname;

			if ((fname = wget_utf8_to_str(iri->path, encoding))) {
				wget_buffer_strcat(buf, fname);
				xfree(fname);
			} else {
				// conversion failed, keep original string
				wget_buffer_strcat(buf, iri->path);
			}
		} else {
			wget_buffer_strcat(buf, iri->path);
		}
	}

	if ((buf->length == 0 || buf->data[buf->length - 1] == '/') && default_page)
		wget_buffer_memcat(buf, default_page, default_page_length);

	return buf->data;
}

/**
 * \param[in] iri An IRI
 * \param[in] buf A buffer, where the resulting string will be put
 * \param[in] encoding Character set the string should be converted to
 * \return The contents of the buffer \p buf
 *
 * Take the query part, and escape the path separators (`/`), so that it can be used as part
 * of a filename.
 *
 * The resulting string will be placed in the buffer \p buf and also returned as a `const char *`.
 * If the provided IRI has no query part, then the original contents of \p buf are returned and \p buf
 * is kept untouched.
 *
 * If \p encoding is provided, this function will try to convert the query (which is originally
 * in UTF-8) to that encoding.
 */
char *wget_iri_get_query_as_filename(const wget_iri *iri, wget_buffer *buf, const char *encoding)
{
	if (iri->query) {
		const char *query;
		int allocated = 0;

		wget_buffer_memcat(buf, "?", 1);

		if (wget_strcasecmp_ascii(encoding, "utf-8")) {
			if ((query = wget_utf8_to_str(iri->query, encoding)))
				allocated = 1;
			else
				query = iri->query;
		} else {
			query = iri->query;
		}

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
						wget_buffer_memcat(buf, begin, src - begin);
					begin = src + 1;
					wget_buffer_memcat(buf, "%2F", 3);
				}
			}

			if (begin != src)
				wget_buffer_memcat(buf, begin, src - begin);
		} else {
			wget_buffer_strcat(buf, query);
		}

		if (allocated)
			xfree(query);
	}

	return buf->data;
}

/**
 * \param[in] iri An IRI
 * \param[in] buf A buffer, where the resulting string will be put
 * \param[in] encoding Character set the string should be converted to
 * \return The contents of the buffer \p buf
 *
 * Get the filename of the path of the provided IRI.
 *
 * This is similar to wget_iri_get_path(), but instead of returning the whole path
 * it only returns the substring after the last occurrence of `/`. In other words, the
 * filename of the path.
 *
 * This is also known as the "basename" in the UNIX world, and the output of this function
 * would be equivalent to the output of the `basename(1)` tool.
 *
 * The path is copied into \p buf if it's empty. If the buffer \p buf is not empty,
 * it is appended to it after a path separator (`/`).
 *
 * If \p encoding is provided, this function will try to convert the path (which is originally
 * in UTF-8) to that encoding.
 */
char *wget_iri_get_basename(const wget_iri *iri, wget_buffer *buf, const char *encoding, int flags)
{
	if (iri->path) {
		char *fname;

		if (wget_strcasecmp_ascii(encoding, "utf-8")) {
			char *p;

			if ((p = strrchr(iri->path, '/'))) {
				if (!(fname = wget_utf8_to_str(p + 1, encoding)))
					wget_buffer_strcat(buf, p + 1); // conversion failed, keep original string
			} else {
				if (!(fname = wget_utf8_to_str(iri->path, encoding)))
					wget_buffer_strcat(buf, iri->path); // conversion failed, keep original string
			}

			if (fname) {
				// conversion succeeded
				wget_buffer_strcat(buf, fname);
				xfree(fname);
			}
		} else {
			if ((fname = strrchr(iri->path, '/')))
				wget_buffer_strcat(buf, fname + 1);
			else
				wget_buffer_strcat(buf, iri->path);
		}
	}

	if ((buf->length == 0 || buf->data[buf->length - 1] == '/') && default_page)
		wget_buffer_memcat(buf, default_page, default_page_length);

	if (flags & WGET_IRI_WITH_QUERY)
		return wget_iri_get_query_as_filename(iri, buf, encoding);

	return buf->data;
}

// escaping: see https://tools.ietf.org/html/rfc2396#2 following (especially 2.4.2)
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

void wget_iri_set_defaultpage(const char *page)
{
	default_page = page;
	default_page_length = default_page ? strlen(default_page) : 0;
}

/**
 * \param scheme The scheme for the new default port
 * \param port The new default port value for the given scheme
 * \return 0: success  -1: Unknown scheme
 *
 * Set the default \p port for the given \p scheme.
 */
int wget_iri_set_defaultport(wget_iri_scheme scheme, uint16_t port)
{
	if ((unsigned) scheme < countof(schemes)) {
		schemes[scheme].port = port;
		return 0;
	}

	return -1;
}

/**
 * \param[in] iri An IRI
 * \param[in] scheme A scheme, such as `http` or `https`.
 * \return The original scheme of IRI (ie. before the replacement)
 *
 * Set the scheme of the provided IRI. The IRI's original scheme
 * is replaced by the new one.
 *
 * If the IRI was using a default port (such as 80 for HTTP or 443 for HTTPS)
 * that port is modified as well to match the default port of the new scheme.
 * Otherwise the port is left untouched.
 */
wget_iri_scheme wget_iri_set_scheme(wget_iri *iri, wget_iri_scheme scheme)
{
	wget_iri_scheme old_scheme = iri->scheme;

	if ((unsigned) scheme < countof(schemes) && iri->scheme != scheme) {
		iri->scheme = scheme;

		// If the IRI is using the default port, also change it
		if (iri->port == schemes[old_scheme].port)
			iri->port = schemes[scheme].port;

		size_t old_scheme_len = strlen(schemes[old_scheme].name);

		if (strncmp(iri->uri, schemes[old_scheme].name, old_scheme_len) == 0 && iri->uri[old_scheme_len] == ':') {
			char *new_uri = wget_aprintf("%s%s",  schemes[iri->scheme].name, iri->uri + old_scheme_len);
			if (iri->uri_allocated)
				xfree(iri->uri);
			iri->uri = new_uri;
			iri->uri_allocated = true;
		}
	}

	if (iri->userinfo) {
		xfree(iri->safe_uri);
		iri->safe_uri = create_safe_uri(iri);
	} else {
		iri->safe_uri = iri->uri;
	}
	return old_scheme;
}

static char *create_safe_uri(wget_iri *iri)
{
	if (!iri || !iri->uri)
		return NULL;

	wget_buffer *buf = wget_buffer_alloc(strlen(iri->uri));
	if (!buf)
		return NULL;

	wget_buffer_printf(buf, "%s://%s", schemes[iri->scheme].name, iri->host);

	if (iri->path) {
		wget_buffer_strcat(buf, "/");
		wget_buffer_strcat(buf, iri->path);
	}
	if (iri->query) {
		wget_buffer_strcat(buf, "?");
		wget_buffer_strcat(buf, iri->query);
	}
	if (iri->fragment) {
		wget_buffer_strcat(buf, "#");
		wget_buffer_strcat(buf, iri->fragment);
	}

	char *safe_uri = buf->data;
	buf->data = NULL;
	wget_buffer_free(&buf);

	return safe_uri;
}

/** @} */

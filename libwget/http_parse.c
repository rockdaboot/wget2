/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 * HTTP parsing routines
 *
 * Resources:
 * RFC 2616
 * RFC 6265
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <c-ctype.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

#include <wget.h>
#include "private.h"
#include "http.h"

#define HTTP_CTYPE_SEPARATOR (1<<0)

static const unsigned char
	http_ctype[256] = {
		['('] = HTTP_CTYPE_SEPARATOR,
		[')'] = HTTP_CTYPE_SEPARATOR,
		['<'] = HTTP_CTYPE_SEPARATOR,
		['>'] = HTTP_CTYPE_SEPARATOR,
		['@'] = HTTP_CTYPE_SEPARATOR,
		[','] = HTTP_CTYPE_SEPARATOR,
		[';'] = HTTP_CTYPE_SEPARATOR,
		[':'] = HTTP_CTYPE_SEPARATOR,
		['\\'] = HTTP_CTYPE_SEPARATOR,
		['\"'] = HTTP_CTYPE_SEPARATOR,
		['/'] = HTTP_CTYPE_SEPARATOR,
		['['] = HTTP_CTYPE_SEPARATOR,
		[']'] = HTTP_CTYPE_SEPARATOR,
		['?'] = HTTP_CTYPE_SEPARATOR,
		['='] = HTTP_CTYPE_SEPARATOR,
		['{'] = HTTP_CTYPE_SEPARATOR,
		['}'] = HTTP_CTYPE_SEPARATOR,
		[' '] = HTTP_CTYPE_SEPARATOR,
		['\t'] = HTTP_CTYPE_SEPARATOR
	};

static inline bool http_isseparator(char c)
{
	return (http_ctype[(unsigned char)(c)]&HTTP_CTYPE_SEPARATOR) != 0;
}

/**Gets the hostname of the remote endpoint.
 * \param conn a wget_http_connection
 * \return A string containing hostname. Returned memory is owned by
 *         _conn_ and should not be modified or freed.
 */
const char *wget_http_get_host(const wget_http_connection *conn)
{
	return conn->esc_host;
}

/**Gets the port number of the remote endpoint.
 * \param conn a wget_http_connection
 * \return A string containing port number. Returned memory is owned by
 *         _conn_ and should not be modified or freed.
 */
uint16_t wget_http_get_port(const wget_http_connection *conn)
{
	return conn->port;
}

/**Get the scheme used by the connection.
 * \param conn a wget_http_connection
 * \return A WGET_IRI_SCHEM_* value.
 */
wget_iri_scheme wget_http_get_scheme(const wget_http_connection *conn)
{
	return conn->scheme;
}

/**Gets the protocol used by the connection
 * \param conn a wget_http_connection
 * \return Either WGET_PROTOCOL_HTTP_1_1 or WGET_PROTOCOL_HTTP_2_0
 */
int wget_http_get_protocol(const wget_http_connection *conn)
{
	return conn->protocol;
}

bool wget_http_isseparator(char c)
{
	return http_isseparator(c);
}

// TEXT           = <any OCTET except CTLs, but including LWS>
//int http_istext(char c)
//{
//	return (c>=32 && c<=126) || c=='\r' || c=='\n' || c=='\t';
//}

// token          = 1*<any CHAR except CTLs or separators>

bool wget_http_istoken(char c)
{
	return c > 32 && c <= 126 && !http_isseparator(c);
}

const char *wget_http_parse_token(const char *s, const char **token)
{
	const char *p;

	for (p = s; wget_http_istoken(*s); s++);

	*token = wget_strmemdup(p, s - p);

	return s;
}

// quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
// qdtext         = <any TEXT except <">>
// quoted-pair    = "\" CHAR
// TEXT           = <any OCTET except CTLs, but including LWS>
// CTL            = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
// LWS            = [CRLF] 1*( SP | HT )

const char *wget_http_parse_quoted_string(const char *s, const char **qstring)
{
	if (*s == '\"') {
		const char *p = ++s;

		// relaxed scanning
		while (*s) {
			if (*s == '\"') break;
			else if (*s == '\\' && s[1]) {
				s += 2;
			} else
				s++;
		}

		*qstring = wget_strmemdup(p, s - p);
		if (*s == '\"') s++;
	} else
		*qstring = NULL;

	return s;
}

// generic-param  =  token [ EQUAL gen-value ]
// gen-value      =  token / host / quoted-string

const char *wget_http_parse_param(const char *s, const char **param, const char **value)
{
	const char *p;

	*param = *value = NULL;

	while (c_isblank(*s)) s++;

	if (*s == ';') {
		s++;
		while (c_isblank(*s)) s++;
	}
	if (!*s) return s;

	for (p = s; wget_http_istoken(*s); s++);
	*param = wget_strmemdup(p, s - p);

	while (c_isblank(*s)) s++;

	if (*s && *s++ == '=') {
		while (c_isblank(*s)) s++;
		if (*s == '\"') {
			s = wget_http_parse_quoted_string(s, value);
		} else {
			s = wget_http_parse_token(s, value);
		}
	}

	return s;
}

// message-header = field-name ":" [ field-value ]
// field-name     = token
// field-value    = *( field-content | LWS )
// field-content  = <the OCTETs making up the field-value
//                  and consisting of either *TEXT or combinations
//                  of token, separators, and quoted-string>

const char *wget_http_parse_name(const char *s, const char **name)
{
	while (c_isblank(*s)) s++;

	s = wget_http_parse_token(s, name);

	while (*s && *s != ':') s++;

	return *s == ':' ? s + 1 : s;
}

const char *wget_parse_name_fixed(const char *s, const char **name, size_t *namelen)
{
	while (c_isblank(*s)) s++;

	*name = s;

	while (wget_http_istoken(*s))
		s++;

	*namelen = s - *name;

	while (*s && *s != ':') s++;

	return *s == ':' ? s + 1 : s;
}

static int WGET_GCC_NONNULL_ALL compare_param(wget_http_header_param *p1, wget_http_header_param *p2)
{
	return wget_strcasecmp_ascii(p1->name, p2->name);
}

void wget_http_add_param(wget_vector **params, wget_http_header_param *param)
{
	if (!*params) *params = wget_vector_create(4, (wget_vector_compare_fn *) compare_param);
	wget_vector_add_memdup(*params, param, sizeof(*param));
}

/*
  Link           = "Link" ":" #link-value
  link-value     = "<" URI-Reference ">" *( ";" link-param )
  link-param     = ( ( "rel" "=" relation-types )
					  | ( "anchor" "=" <"> URI-Reference <"> )
					  | ( "rev" "=" relation-types )
					  | ( "hreflang" "=" Language-Tag )
					  | ( "media" "=" ( MediaDesc | ( <"> MediaDesc <"> ) ) )
					  | ( "title" "=" quoted-string )
					  | ( "title*" "=" ext-value )
					  | ( "type" "=" ( media-type | quoted-mt ) )
					  | ( link-extension ) )
  link-extension = ( parmname [ "=" ( ptoken | quoted-string ) ] )
					  | ( ext-name-star "=" ext-value )
  ext-name-star  = parmname "*" ; reserved for RFC2231-profiled
										  ; extensions.  Whitespace NOT
										  ; allowed in between.
  ptoken         = 1*ptokenchar
  ptokenchar     = "!" | "#" | "$" | "%" | "&" | "'" | "("
					  | ")" | "*" | "+" | "-" | "." | "/" | DIGIT
					  | ":" | "<" | "=" | ">" | "?" | "@" | ALPHA
					  | "[" | "]" | "^" | "_" | "`" | "{" | "|"
					  | "}" | "~"
  media-type     = type-name "/" subtype-name
  quoted-mt      = <"> media-type <">
  relation-types = relation-type
					  | <"> relation-type *( 1*SP relation-type ) <">
  relation-type  = reg-rel-type | ext-rel-type
  reg-rel-type   = LOALPHA *( LOALPHA | DIGIT | "." | "-" )
  ext-rel-type   = URI
*/
const char *wget_http_parse_link(const char *s, wget_http_link *link)
{
	memset(link, 0, sizeof(*link));

	while (c_isblank(*s)) s++;

	if (*s == '<') {
		// URI reference as of RFC 3987 (if relative, resolve as of RFC 3986)
		const char *p = s + 1;
		if ((s = strchr(p, '>')) != NULL) {
			const char *name = NULL, *value = NULL;

			link->uri = wget_strmemdup(p, s - p);
			s++;

			while (c_isblank(*s)) s++;

			while (*s == ';') {
				s = wget_http_parse_param(s, &name, &value);
				if (name && value) {
					if (!wget_strcasecmp_ascii(name, "rel")) {
						if (!wget_strcasecmp_ascii(value, "describedby"))
							link->rel = link_rel_describedby;
						else if (!wget_strcasecmp_ascii(value, "duplicate"))
							link->rel = link_rel_duplicate;
					} else if (!wget_strcasecmp_ascii(name, "pri")) {
						link->pri = atoi(value);
					} else if (!wget_strcasecmp_ascii(name, "type")) {
						if (!link->type) {
							link->type = value;
							value = NULL;
						}
					}
					//				http_add_param(&link->params,&param);
					while (c_isblank(*s)) s++;
				}

				xfree(name);
				xfree(value);
			}

			//			if (!msg->contacts) msg->contacts=vec_create(1,1,NULL);
			//			vec_add(msg->contacts,&contact,sizeof(contact));

			while (*s && !c_isblank(*s)) s++;
		}
	}

	return s;
}

// from RFC 3230:
// Digest = "Digest" ":" #(instance-digest)
// instance-digest = digest-algorithm "=" <encoded digest output>
// digest-algorithm = token

const char *wget_http_parse_digest(const char *s, wget_http_digest *digest)
{
	memset(digest, 0, sizeof(*digest));

	while (c_isblank(*s)) s++;
	s = wget_http_parse_token(s, &digest->algorithm);

	while (c_isblank(*s)) s++;

	if (*s == '=') {
		s++;
		while (c_isblank(*s)) s++;
		if (*s == '\"') {
			s = wget_http_parse_quoted_string(s, &digest->encoded_digest);
		} else {
			const char *p;

			for (p = s; *s && !c_isblank(*s) && *s != ',' && *s != ';'; s++);
			digest->encoded_digest = wget_strmemdup(p, s - p);
		}
	}

	while (*s && !c_isblank(*s)) s++;

	return s;
}

// RFC 2617:
// challenge   = auth-scheme 1*SP 1#auth-param
// auth-scheme = token
// auth-param  = token "=" ( token | quoted-string )

const char *wget_http_parse_challenge(const char *s, wget_http_challenge *challenge)
{
	memset(challenge, 0, sizeof(*challenge));

	while (c_isblank(*s)) s++;
	s = wget_http_parse_token(s, &challenge->auth_scheme);

	if (*s == ' ')
		s++; // Auth scheme must have a space at the end of the token
	else {
		// parse/syntax error
		xfree(challenge->auth_scheme);
		return s;
	}

	wget_http_header_param param;
	do {
		const char *old = s;
		s = wget_http_parse_param(s, &param.name, &param.value);
		if (param.name) {
			if (*param.name && !param.value) {
				xfree(param.name);
				return old; // a new scheme detected
			}

			if (!param.value) {
				xfree(param.name);
				continue;
			}

			if (!challenge->params)
				challenge->params = wget_stringmap_create_nocase(8);
			wget_stringmap_put(challenge->params, param.name, param.value);
		}

		while (c_isblank(*s)) s++;

		if (*s != ',') break;
		else if (*s) s++;
	} while (*s);

	return s;
}

const char *wget_http_parse_challenges(const char *s, wget_vector *challenges)
{
	wget_http_challenge challenge;

	while (*s) {
		s = wget_http_parse_challenge(s, &challenge);
		if (challenge.auth_scheme) {
			wget_vector_add_memdup(challenges, &challenge, sizeof(challenge));
		}
	}

	return s;
}

const char *wget_http_parse_location(const char *s, const char **location)
{
	const char *p;

	while (c_isblank(*s)) s++;

	/*
	 * The correct (and still lenient) variant was:
	 * for (p = s; *s && !c_isblank(*s); s++);
	 *
	 * And then there were spaces in the URI, see
	 *   https://gitlab.com/gnuwget/wget2/issues/420
	 */

	for (p = s; *s && *s != '\r' && *s != '\n'; s++);
	while (s > p && c_isblank(*(s - 1))) s--; // remove trailing spaces (OWS - optional white space)

	*location = wget_strmemdup(p, s - p);

	return s;
}

// Transfer-Encoding       = "Transfer-Encoding" ":" 1#transfer-coding
// transfer-coding         = "chunked" | transfer-extension
// transfer-extension      = token *( ";" parameter )
// parameter               = attribute "=" value
// attribute               = token
// value                   = token | quoted-string

const char *wget_http_parse_transfer_encoding(const char *s, wget_transfer_encoding *transfer_encoding)
{
	while (c_isblank(*s)) s++;

	if (!wget_strcasecmp_ascii(s, "identity"))
		*transfer_encoding = wget_transfer_encoding_identity;
	else
		*transfer_encoding = wget_transfer_encoding_chunked;

	while (wget_http_istoken(*s)) s++;

	return s;
}

// Content-Type   = "Content-Type" ":" media-type
// media-type     = type "/" subtype *( ";" parameter )
// type           = token
// subtype        = token
// example: Content-Type: text/html; charset=ISO-8859-4

const char *wget_http_parse_content_type(const char *s, const char **content_type, const char **charset)
{
	wget_http_header_param param;
	const char *p;

	while (c_isblank(*s)) s++;

	for (p = s; *s && (wget_http_istoken(*s) || *s == '/'); s++);
	if (content_type)
		*content_type = wget_strmemdup(p, s - p);

	if (charset) {
		*charset = NULL;

		while (*s) {
			s=wget_http_parse_param(s, &param.name, &param.value);
			if (!wget_strcasecmp_ascii("charset", param.name)) {
				xfree(param.name);
				*charset = param.value;
				break;
			}
			xfree(param.name);
			xfree(param.value);
		}
	}

	return s;
}

// RFC 6266 - Use of the Content-Disposition Header Field in the Hypertext Transfer Protocol (HTTP)
// content-disposition = "Content-Disposition" ":" disposition-type *( ";" disposition-parm )
// disposition-type    = "inline" | "attachment" | disp-ext-type ; case-insensitive
// disp-ext-type       = token
// disposition-parm    = filename-parm | disp-ext-parm
// filename-parm       = "filename" "=" value | "filename*" "=" ext-value
// disp-ext-parm       = token "=" value | ext-token "=" ext-value
// ext-token           = <the characters in token, followed by "*">
//
// Defined in [RFC2616]:
//
// token         = <token, defined in [RFC2616], Section 2.2>
// quoted-string = <quoted-string, defined in [RFC2616], Section 2.2>
// value         = <value, defined in [RFC2616], Section 3.6> ; token | quoted-string
//
// Defined in [RFC5987]:
//
// ext-value   = <ext-value, defined in [RFC5987], Section 3.2>

const char *wget_http_parse_content_disposition(const char *s, const char **filename)
{
	wget_http_header_param param;
	char *p;

	if (filename) {
		*filename = NULL;

		while (*s && !*filename) {
			s = wget_http_parse_param(s, &param.name, &param.value);
			if (param.value && !wget_strcasecmp_ascii("filename", param.name)) {
				// just take the last path part as filename
				if (!*filename) {
					if ((p = strpbrk(param.value,"/\\"))) {
						p = wget_strdup(p + 1);
					} else {
						p = (char *) param.value;
						param.value = NULL;
					}

					wget_percent_unescape(p);
					if (!wget_str_is_valid_utf8(p)) {
						// if it is not UTF-8, assume ISO-8859-1
						// see https://stackoverflow.com/questions/93551/how-to-encode-the-filename-parameter-of-content-disposition-header-in-http
						*filename = wget_str_to_utf8(p, "iso-8859-1");
						xfree(p);
					} else {
						*filename = p;
						p = NULL;
					}
				}
			} else if (param.value && !wget_strcasecmp_ascii("filename*", param.name)) {
				// RFC5987
				// ext-value     = charset  "'" [ language ] "'" value-chars
				// ; like RFC 2231's <extended-initial-value>
				// ; (see [RFC2231], Section 7)

				// charset       = "UTF-8" / "ISO-8859-1" / mime-charset

				// mime-charset  = 1*mime-charsetc
				// mime-charsetc = ALPHA / DIGIT
				//		/ "!" / "#" / "$" / "%" / "&"
				//		/ "+" / "-" / "^" / "_" / "`"
				//		/ "{" / "}" / "~"
				//		; as <mime-charset> in Section 2.3 of [RFC2978]
				//		; except that the single quote is not included
				//		; SHOULD be registered in the IANA charset registry

				// language      = <Language-Tag, defined in [RFC5646], Section 2.1>

				// value-chars   = *( pct-encoded / attr-char )

				// pct-encoded   = "%" HEXDIG HEXDIG
				//		; see [RFC3986], Section 2.1

				// attr-char     = ALPHA / DIGIT
				//		/ "!" / "#" / "$" / "&" / "+" / "-" / "."
				//		/ "^" / "_" / "`" / "|" / "~"
				//		; token except ( "*" / "'" / "%" )

				if ((p = strchr(param.value, '\''))) {
					const char *charset = param.value;
					const char *language = p + 1;
					*p = 0;
					if ((p = strchr(language, '\''))) {
						*p++ = 0;
						if (*p) {
							wget_percent_unescape(p);
							if (wget_str_needs_encoding(p))
								*filename = wget_str_to_utf8(p, charset);
							else
								*filename = wget_strdup(p);

							// just take the last path part as filename
							if (*filename && (p = strpbrk(*filename, "/\\"))) {
								p = wget_strdup(p + 1);
								xfree(*filename);
								*filename = p;
							}

							xfree(param.name);
							xfree(param.value);
							break; // stop looping, we found the final filename
						}
					}
				}
			}
			xfree(param.name);
			xfree(param.value);
		}
	}

	return s;
}

// RFC 7469
// Example:
//   Public-Key-Pins:
//        pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
//	       pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
//	       pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
//	       max-age=10000; includeSubDomains
const char *wget_http_parse_public_key_pins(const char *s, wget_hpkp *hpkp)
{
	wget_http_header_param param;

	wget_hpkp_set_include_subdomains(hpkp, false);

	while (*s) {
		s = wget_http_parse_param(s, &param.name, &param.value);

		if (param.value) {
			if (!wget_strcasecmp_ascii(param.name, "max-age")) {
				wget_hpkp_set_maxage(hpkp, (int64_t) atoll(param.value));
			} else if (!wget_strncasecmp_ascii(param.name, "pin-", 4)) {
				wget_hpkp_pin_add(hpkp, param.name + 4, param.value);
			}
		} else {
			if (!wget_strcasecmp_ascii(param.name, "includeSubDomains"))
				wget_hpkp_set_include_subdomains(hpkp, true);
		}

		xfree(param.name);
		xfree(param.value);
	}

	return s;
}

// RFC 6797
//
// Strict-Transport-Security = "Strict-Transport-Security" ":" [ directive ]  *( ";" [ directive ] )
// directive                 = directive-name [ "=" directive-value ]
// directive-name            = token
// directive-value           = token | quoted-string

const char *wget_http_parse_strict_transport_security(const char *s, int64_t *maxage, bool *include_subdomains)
{
	wget_http_header_param param;

	*maxage = 0;
	*include_subdomains = 0;

	while (*s) {
		s = wget_http_parse_param(s, &param.name, &param.value);

		if (param.value) {
			if (!wget_strcasecmp_ascii(param.name, "max-age")) {
				*maxage = (int64_t) atoll(param.value);
			}
		} else {
			if (!wget_strcasecmp_ascii(param.name, "includeSubDomains")) {
				*include_subdomains = 1;
			}
		}

		xfree(param.name);
		xfree(param.value);
	}

	return s;
}

// Content-Encoding  = "Content-Encoding" ":" 1#content-coding

const char *wget_http_parse_content_encoding(const char *s, char *content_encoding)
{
	while (c_isblank(*s)) s++;

	if (!wget_strcasecmp_ascii(s, "gzip") || !wget_strcasecmp_ascii(s, "x-gzip"))
		*content_encoding = wget_content_encoding_gzip;
	else if (!wget_strcasecmp_ascii(s, "deflate"))
		*content_encoding = wget_content_encoding_deflate;
	else if (!wget_strcasecmp_ascii(s, "bzip2"))
		*content_encoding = wget_content_encoding_bzip2;
	else if (!wget_strcasecmp_ascii(s, "xz") || !wget_strcasecmp_ascii(s, "lzma") || !wget_strcasecmp_ascii(s, "x-lzma"))
		// 'xz' is the tag currently understood by Firefox (2.1.2014)
		// 'lzma' / 'x-lzma' are the tags currently understood by ELinks
		*content_encoding = wget_content_encoding_lzma;
	else if (!wget_strcasecmp_ascii(s, "br"))
		*content_encoding = wget_content_encoding_brotli;
	else if (!wget_strcasecmp_ascii(s, "zstd"))
		*content_encoding = wget_content_encoding_zstd;
	else if (!wget_strcasecmp_ascii(s, "lzip"))
		*content_encoding = wget_content_encoding_lzip;
	else
		*content_encoding = wget_content_encoding_identity;

	while (wget_http_istoken(*s)) s++;

	return s;
}

const char *wget_http_parse_connection(const char *s, bool *keep_alive)
{
	const char *e;

	*keep_alive = false;

	for (e = s; *e; s = e + 1) {
		if ((e = strchrnul(s, ',')) != s) {
			while (c_isblank(*s)) s++;

			if (!wget_strncasecmp_ascii(s, "keep-alive", 10))
				*keep_alive = true;
		}
	}

	return s;
}

const char *wget_http_parse_etag(const char *s, const char **etag)
{
	const char *p;

	while (c_isblank(*s)) s++;

	for (p = s; *s && !c_isblank(*s); s++);
	*etag = wget_strmemdup(p, s - p);

	return s;
}

/*
// returns GMT/UTC time as an integer of format YYYYMMDDHHMMSS
// this makes us independent from size of time_t - work around possible year 2038 problems
static long long NONNULL_ALL parse_rfc1123_date(const char *s)
{
	// we simply can't use strptime() since it requires us to setlocale()
	// which is not thread-safe !!!
	static const char *mnames[12] = {
		"Jan", "Feb", "Mar","Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	static int days_per_month[12] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};
	int day, mon = 0, year, hour, min, sec, leap, it;
	char mname[4] = "";

	if (sscanf(s, " %*[a-zA-Z], %02d %3s %4d %2d:%2d:%2d", &day, mname, &year, &hour, &min, &sec) >= 6) {
		// RFC 822 / 1123: Wed, 09 Jun 2021 10:18:14 GMT
	}
	else if (sscanf(s, " %*[a-zA-Z], %2d-%3s-%4d %2d:%2d:%2d", &day, mname, &year, &hour, &min, &sec) >= 6) {
		// RFC 850 / 1036 or Netscape: Wednesday, 09-Jun-21 10:18:14 or Wed, 09-Jun-2021 10:18:14
	}
	else if (sscanf(s, " %*[a-zA-Z], %3s %2d %2d:%2d:%2d %4d", mname, &day, &hour, &min, &sec, &year) >= 6) {
		// ANSI C's asctime(): Wed Jun 09 10:18:14 2021
	} else {
		error_printf(_("Failed to parse date '%s'\n"), s);
		return 0; // return as session cookie
	}

	if (*mname) {
		for (it = 0; it < countof(mnames); it++) {
			if (!wget_strcasecmp_ascii(mname, mnames[it])) {
				mon = it + 1;
				break;
			}
		}
	}

	if (year < 70 && year >= 0) year += 2000;
	else if (year >= 70 && year <= 99) year += 1900;

	if (mon == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
		leap = 1;
	else
		leap = 0;

	// we don't handle leap seconds

	if (year < 1601 || mon < 1 || mon > 12 || day < 1 || (day > days_per_month[mon - 1] + leap) ||
		hour < 0 || hour > 23 || min < 0 || min > 60 || sec < 0 || sec > 60)
	{
		error_printf(_("Failed to parse date '%s'\n"), s);
		return 0; // return as session cookie
	}

	return(((((long long)year*100 + mon)*100 + day)*100 + hour)*100 + min)*100 + sec;
}
*/

// copied this routine from
// https://ftp.netbsd.org/pub/pkgsrc/current/pkgsrc/pkgtools/libnbcompat/files/timegm.c

static int leap_days(int y1, int y2)
{
	y1--;
	y2--;
	return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
RFC 2616, 3.3.1 Full Date
HTTP-date    = rfc1123-date | rfc850-date | asctime-date
rfc1123-date = wkday "," SP date1 SP time SP "GMT"
rfc850-date  = weekday "," SP date2 SP time SP "GMT"
asctime-date = wkday SP date3 SP time SP 4DIGIT
date1        = 2DIGIT SP month SP 4DIGIT
					; day month year (e.g., 02 Jun 1982)
date2        = 2DIGIT "-" month "-" 2DIGIT
					; day-month-year (e.g., 02-Jun-82)
date3        = month SP ( 2DIGIT | ( SP 1DIGIT ))
					; month day (e.g., Jun  2)
time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
					; 00:00:00 - 23:59:59
wkday        = "Mon" | "Tue" | "Wed"
				 | "Thu" | "Fri" | "Sat" | "Sun"
weekday      = "Monday" | "Tuesday" | "Wednesday"
				 | "Thursday" | "Friday" | "Saturday" | "Sunday"
month        = "Jan" | "Feb" | "Mar" | "Apr"
				 | "May" | "Jun" | "Jul" | "Aug"
				 | "Sep" | "Oct" | "Nov" | "Dec"
*/

int64_t wget_http_parse_full_date(const char *s)
{
	// we simply can't use strptime() since it requires us to setlocale()
	// which is not thread-safe !!!
	static const char *mnames[12] = {
		"Jan", "Feb", "Mar","Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	static int days_per_month[12] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};
	// cumulated number of days until beginning of month for non-leap years
	static const int sum_of_days[12] = {
		0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
	};

	int day, mon = 0, year, hour, min, sec, leap_month, leap_year, days;
	char mname[4] = "";

	if (sscanf(s, " %*[a-zA-Z], %2d %3s %4d %2d:%2d:%2d", &day, mname, &year, &hour, &min, &sec) == 6) {
		// RFC 822 / 1123: Wed, 09 Jun 2021 10:18:14 GMT
	} else if (sscanf(s, " %*[a-zA-Z], %2d-%3s-%4d %2d:%2d:%2d", &day, mname, &year, &hour, &min, &sec) == 6) {
		// RFC 850 / 1036 or Netscape: Wednesday, 09-Jun-21 10:18:14 or Wed, 09-Jun-2021 10:18:14
	} else if (sscanf(s, " %*[a-zA-Z] %3s %2d %2d:%2d:%2d %4d", mname, &day, &hour, &min, &sec, &year) == 6) {
		// ANSI C's asctime(): Wed Jun 09 10:18:14 2021
	} else if (sscanf(s, " %d %3s %4d %2d:%2d:%2d", &day, mname, &year, &hour, &min, &sec) == 6) {
		// non-standard: 1 Mar 2027 09:23:12 GMT
	} else if (sscanf(s, " %*s %3s %2d %4d %2d:%2d:%2d", mname, &day, &year, &hour, &min, &sec) == 6) {
		// non-standard: Sun Nov 26 2023 21:24:47
	} else {
		error_printf(_("Failed to parse date '%s'\n"), s);
		return 0; // return as session cookie
	}

	if (*mname) {
		for (unsigned it = 0; it < countof(mnames); it++) {
			if (!wget_strcasecmp_ascii(mname, mnames[it])) {
				mon = it + 1;
				break;
			}
		}
	}

	if (year < 70 && year >= 0) year += 2000;
	else if (year >= 70 && year <= 99) year += 1900;
	if (year < 1970) year = 1970;

	// we don't handle leap seconds

	leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
	leap_month = (mon == 2 && leap_year);

	if (mon < 1 || mon > 12 || day < 1 || (day > days_per_month[mon - 1] + leap_month) ||
		hour < 0 || hour > 23 || min < 0 || min > 60 || sec < 0 || sec > 60)
	{
		error_printf(_("Failed to parse date '%s'\n"), s);
		return 0; // return as session cookie
	}

	// calculate time_t (represented as int64_t) from GMT/UTC time values

	days = 365 * (year - 1970) + leap_days(1970, year);
	days += sum_of_days[mon - 1] + (mon > 2 && leap_year);
	days += day - 1;

	return (((int64_t)days * 24 + hour) * 60 + min) * 60 + sec;
}

char *wget_http_print_date(int64_t t, char *buf, size_t bufsize)
{
	static const char *dnames[7] = {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
	};
	static const char *mnames[12] = {
		"Jan", "Feb", "Mar","Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	struct tm tm;
	time_t tt;

	if (!bufsize)
		return buf;

#if __LP64__ == 1
	tt = (time_t) t; // 64bit time_t
#else
	// 32bit time_t
	if (t > 2147483647)
		tt = 2147483647;
	else
		tt = (time_t) t;
#endif

	if (gmtime_r(&tt, &tm)) {
		wget_snprintf(buf, bufsize, "%s, %02d %s %d %02d:%02d:%02d GMT",
			dnames[tm.tm_wday],tm.tm_mday,mnames[tm.tm_mon],tm.tm_year+1900,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
	} else
		*buf = 0;

	return buf;
}

// adjust time (t) by number of seconds (n)
/*
static long long adjust_time(long long t, int n)
{
	static int days_per_month[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	int day, mon, year, hour, min, sec, leap;

	sec = t % 100;
	min = (t /= 100) % 100;
	hour = (t /= 100) % 100;
	day = (t /= 100) % 100;
	mon = (t /= 100) % 100;
	year = t / 100;

	sec += n;

	if (n >= 0) {
		if (sec >= 60) {
			min += sec / 60;
			sec %= 60;
		}
		if (min >= 60) {
			hour += min / 60;
			min %= 60;
		}
		if (hour >= 24) {
			day += hour / 24;
			hour %= 24;
		}
		while (1) {
			if (mon == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
				leap = 1;
			else
				leap = 0;
			if (day > days_per_month[mon - 1] + leap) {
				day -= (days_per_month[mon - 1] + leap);
				mon++;
				if (mon > 12) {
					mon = 1;
					year++;
				}
			} else break;
		}
	} else { // n<0
		if (sec < 0) {
			min += (sec - 59) / 60;
			sec = 59 + (sec + 1) % 60;
		}
		if (min < 0) {
			hour += (min - 59) / 60;
			min = 59 + (min + 1) % 60;
		}
		if (hour < 0) {
			day += (hour - 23) / 24;
			hour = 23 + (hour + 1) % 24;
		}
		for (;;) {
			if (day <= 0) {
				if (--mon < 1) {
					mon = 12;
					year--;
				}
				if (mon == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
					leap = 1;
				else
					leap = 0;
				day += (days_per_month[mon - 1] + leap);
			} else break;
		}
	}

	return (((((long long)year*100 + mon)*100 + day)*100 + hour)*100 + min)*100 + sec;
}

// return current GMT/UTC

static int64_t get_current_time(void)
{
	int64_t t = time(NULL);
	struct tm tm;

	gmtime_r(&t, &tm);

	return (((((int64_t)(tm.tm_year + 1900)*100 + tm.tm_mon + 1)*100 + tm.tm_mday)*100 + tm.tm_hour)*100 + tm.tm_min)*100 + tm.tm_sec;
}
*/

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
const char *wget_http_parse_setcookie(const char *s, wget_cookie **cookie)
{
	return wget_cookie_parse_setcookie(s, cookie);
}

static void cookie_free(void *cookie)
{
	if (cookie)
		wget_cookie_free((wget_cookie **) &cookie);
}

int wget_http_parse_header_line(wget_http_response *resp, const char *name, size_t namelen, const char *value, size_t valuelen)
{
	if (!name || !value)
		return WGET_E_INVALID;

	char valuebuf[256];
	char *value0;
	int ret = WGET_E_SUCCESS;

	value0 = wget_strmemcpy_a(valuebuf, sizeof(valuebuf), value, valuelen);
	if (!value0)
		return WGET_E_MEMORY;

	switch (*name | 0x20) {
	case ':':
		if (!memcmp(name, ":status", namelen) && valuelen == 3) {
			resp->code = ((value[0] - '0') * 10 + (value[1] - '0')) * 10 + (value[2] - '0');
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 'c':
		if (!wget_strncasecmp_ascii(name, "content-encoding", namelen)) {
			wget_http_parse_content_encoding(value0, &resp->content_encoding);
		} else if (!wget_strncasecmp_ascii(name, "content-type", namelen)) {
			if (!resp->content_type && !resp->content_type_encoding)
				wget_http_parse_content_type(value0, &resp->content_type, &resp->content_type_encoding);
		} else if (!wget_strncasecmp_ascii(name, "content-length", namelen)) {
			resp->content_length = (size_t)atoll(value0);
			resp->content_length_valid = 1;
		} else if (!wget_strncasecmp_ascii(name, "content-disposition", namelen)) {
			if (!resp->content_filename)
				wget_http_parse_content_disposition(value0, &resp->content_filename);
		} else if (!wget_strncasecmp_ascii(name, "connection", namelen)) {
			wget_http_parse_connection(value0, &resp->keep_alive);
		} else if (!wget_strncasecmp_ascii(name, "Content-Security-Policy", namelen)) {
			resp->csp = 1;
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 'd':
		if (!wget_strncasecmp_ascii(name, "digest", namelen)) {
			// https://tools.ietf.org/html/rfc3230
			wget_http_digest digest;
			wget_http_parse_digest(value0, &digest);
			// debug_printf("%s: %s\n",digest.algorithm,digest.encoded_digest);
			if (!resp->digests) {
				resp->digests = wget_vector_create(4, NULL);
				wget_vector_set_destructor(resp->digests, (wget_vector_destructor *) wget_http_free_digest);
			}
			wget_vector_add_memdup(resp->digests, &digest, sizeof(digest));
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 'e':
		if (!wget_strncasecmp_ascii(name, "etag", namelen)) {
			if (!resp->etag)
				wget_http_parse_etag(value0, &resp->etag);
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 'i':
		if (!wget_strncasecmp_ascii(name, "icy-metaint", namelen)) {
			resp->icy_metaint = atoi(value0);
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 'l':
		if (!wget_strncasecmp_ascii(name, "last-modified", namelen)) {
			// Last-Modified: Thu, 07 Feb 2008 15:03:24 GMT
			resp->last_modified = wget_http_parse_full_date(value0);
		} else if (resp->code / 100 == 3 && !wget_strncasecmp_ascii(name, "location", namelen)) {
			if (!resp->location)
				wget_http_parse_location(value0, &resp->location);
		} else if (resp->code / 100 == 3 && !wget_strncasecmp_ascii(name, "link", namelen)) {
			// debug_printf("s=%.31s\n",s);
			wget_http_link link;
			wget_http_parse_link(value0, &link);
			// debug_printf("link->uri=%s\n",link.uri);
			if (!resp->links) {
				resp->links = wget_vector_create(8, NULL);
				wget_vector_set_destructor(resp->links, (wget_vector_destructor *) wget_http_free_link);
			}
			wget_vector_add_memdup(resp->links, &link, sizeof(link));
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 'p':
		if (!wget_strncasecmp_ascii(name, "public-key-pins", namelen)) {
			if (!resp->hpkp) {
				resp->hpkp = wget_hpkp_new();
				wget_http_parse_public_key_pins(value0, resp->hpkp);
				debug_printf("new host pubkey pinnings added to hpkp db\n");
			}
		}
		else if (!wget_strncasecmp_ascii(name, "proxy-authenticate", namelen)) {
			wget_http_challenge *challenge = wget_malloc(sizeof(wget_http_challenge));

			if (!challenge) {
				ret = WGET_E_MEMORY;
				goto out;
			}

			wget_http_parse_challenge(value0, challenge);

			if (!resp->challenges) {
				resp->challenges = wget_vector_create(2, NULL);
				wget_vector_set_destructor(resp->challenges, (wget_vector_destructor *) wget_http_free_challenge);
			}
			wget_vector_add(resp->challenges, challenge);
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 's':
		if (!wget_strncasecmp_ascii(name, "set-cookie", namelen)) {
			// this is a parser. content validation must be done by higher level functions.
			wget_cookie *cookie;
			wget_http_parse_setcookie(value0, &cookie);

			if (cookie) {
				if (!resp->cookies) {
					resp->cookies = wget_vector_create(4, NULL);
					wget_vector_set_destructor(resp->cookies, cookie_free);
				}
				wget_vector_add(resp->cookies, cookie);
			}
		}
		else if (!wget_strncasecmp_ascii(name, "strict-transport-security", namelen)) {
			resp->hsts = 1;
			wget_http_parse_strict_transport_security(value0, &resp->hsts_maxage, &resp->hsts_include_subdomains);
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 't':
		if (!wget_strncasecmp_ascii(name, "transfer-encoding", namelen)) {
			wget_http_parse_transfer_encoding(value0, &resp->transfer_encoding);
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 'w':
		if (!wget_strncasecmp_ascii(name, "www-authenticate", namelen)) {
			wget_http_challenge *challenge = wget_malloc(sizeof(wget_http_challenge));

			if (!challenge) {
				ret = WGET_E_MEMORY;
				goto out;
			}

			wget_http_parse_challenge(value0, challenge);

			if (!resp->challenges) {
				resp->challenges = wget_vector_create(2, NULL);
				wget_vector_set_destructor(resp->challenges, (wget_vector_destructor *) wget_http_free_challenge);
			}
			wget_vector_add(resp->challenges, challenge);
		} else
			ret = WGET_E_UNKNOWN;
		break;
	case 'x':
		if (!wget_strncasecmp_ascii(name, "x-archive-orig-last-modified", namelen)) {
			resp->last_modified = wget_http_parse_full_date(value0);
		} else
			ret = WGET_E_UNKNOWN;
		break;
	default:
		ret = WGET_E_UNKNOWN;
		break;
	}

out:
	if (value0 != valuebuf)
		xfree(value0);

	return ret;
}

/* content of <buf> will be destroyed */
/* buf must be 0-terminated */
wget_http_response *wget_http_parse_response_header(char *buf)
{
	char *eol;

	wget_http_response *resp = wget_calloc(1, sizeof(wget_http_response));
	if (!resp)
		return NULL;

	if (sscanf(buf, " HTTP/%3hd.%3hd %3hd %31[^\r\n] ",
		&resp->major, &resp->minor, &resp->code, resp->reason) >= 3) {
		if ((eol = strchr(buf + 10, '\n'))) {
			// eol[-1]=0;
			// debug_printf("# %s\n",buf);
		} else {
			// empty HTTP header
			return resp;
		}
	} else if (sscanf(buf, " ICY %3hd %31[^\r\n] ", &resp->code, resp->reason) >= 1) {
		if ((eol = strchr(buf + 4, '\n'))) {
			// eol[-1]=0;
			// debug_printf("# %s\n",buf);
		} else {
			// empty HTTP header
			return resp;
		}
	} else {
		error_printf(_("HTTP response header not found\n"));
		xfree(resp);
		return NULL;
	}

	// 'close' is default on HTTP/1.0, else 'keep_alive' is default
	if ((resp->major == 1 && resp->minor >= 1) || resp->major > 1)
		resp->keep_alive = 1;

	for (char *line = eol + 1; eol && *line && *line != '\r' && *line != '\n'; line = eol ? eol + 1 : NULL) {
		eol = strchr(line, '\n');
		while (eol && c_isblank(eol[1])) { // handle split lines
			*eol = eol[-1] = ' ';
			eol = strchr(eol, '\n');
		}

		if (eol) {
			if (eol[-1] == '\r')
				eol[-1] = 0;
			else
				*eol = 0;
		}

		size_t namelen, valuelen;
		const char *name;
		const char *value = wget_parse_name_fixed(line, &name, &namelen);
		// value now points directly after :

		if (eol)
			valuelen = eol - value - (eol[-1] == 0);
		else
			valuelen = strlen(value);

		wget_http_parse_header_line(resp, name, namelen, value, valuelen);
	}

	return resp;
}

void wget_http_free_param(wget_http_header_param *param)
{
	xfree(param->name);
	xfree(param->value);
	xfree(param);
}

void wget_http_free_link(wget_http_link *link)
{
	xfree(link->uri);
	xfree(link->type);
	xfree(link);
}

void wget_http_free_links(wget_vector **links)
{
	wget_vector_free(links);
}

void wget_http_free_digest(wget_http_digest *digest)
{
	xfree(digest->algorithm);
	xfree(digest->encoded_digest);
	xfree(digest);
}

void wget_http_free_digests(wget_vector **digests)
{
	wget_vector_free(digests);
}

void wget_http_free_challenge(wget_http_challenge *challenge)
{
	xfree(challenge->auth_scheme);
	wget_stringmap_free(&challenge->params);
	xfree(challenge);
}

void wget_http_free_challenges(wget_vector **challenges)
{
	wget_vector_free(challenges);
}

void wget_http_free_cookies(wget_vector **cookies)
{
	wget_vector_free(cookies);
}

void wget_http_free_hpkp_entries(wget_hpkp **hpkp)
{
	if (hpkp) {
		wget_hpkp_free(*hpkp);
		*hpkp = NULL;
	}
}

void wget_http_free_response(wget_http_response **resp)
{
	if (resp && *resp) {
		wget_http_free_links(&(*resp)->links);
		wget_http_free_digests(&(*resp)->digests);
		wget_http_free_challenges(&(*resp)->challenges);
		wget_http_free_cookies(&(*resp)->cookies);
		wget_http_free_hpkp_entries(&(*resp)->hpkp);
		xfree((*resp)->content_type);
		xfree((*resp)->content_type_encoding);
		xfree((*resp)->content_filename);
		xfree((*resp)->location);
		xfree((*resp)->etag);
		// xfree((*resp)->reason);
		wget_buffer_free(&(*resp)->header);
		wget_buffer_free(&(*resp)->body);
		xfree(*resp);
	}
}

/* for security reasons: set all freed pointers to NULL */
void wget_http_free_request(wget_http_request **req)
{
	if (req && *req) {
		wget_buffer_deinit(&(*req)->esc_resource);
		wget_buffer_deinit(&(*req)->esc_host);
		wget_vector_free(&(*req)->headers);
		xfree((*req)->body);
		xfree(*req);
	}
}

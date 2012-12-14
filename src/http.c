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
 * HTTP routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 * 26.10.2012               added Cookie support (RFC 6265)
 *
 * Resources:
 * RFC 2616
 * RFC 6265
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <zlib.h>

#include "options.h"
#include "xalloc.h"
#include "utils.h"
#include "printf.h"
#include "log.h"
#include "decompressor.h"
#include "buffer.h"
#include "cookie.h"
#include "http.h"

#define HTTP_CTYPE_SEPERATOR (1<<0)
#define _http_isseperator(c) (http_ctype[(unsigned char)(c)]&HTTP_CTYPE_SEPERATOR)

static const unsigned char
	http_ctype[256] = {
		['('] = HTTP_CTYPE_SEPERATOR,
		[')'] = HTTP_CTYPE_SEPERATOR,
		['<'] = HTTP_CTYPE_SEPERATOR,
		['>'] = HTTP_CTYPE_SEPERATOR,
		['@'] = HTTP_CTYPE_SEPERATOR,
		[','] = HTTP_CTYPE_SEPERATOR,
		[';'] = HTTP_CTYPE_SEPERATOR,
		[':'] = HTTP_CTYPE_SEPERATOR,
		['\\'] = HTTP_CTYPE_SEPERATOR,
		['\"'] = HTTP_CTYPE_SEPERATOR,
		['/'] = HTTP_CTYPE_SEPERATOR,
		['['] = HTTP_CTYPE_SEPERATOR,
		[']'] = HTTP_CTYPE_SEPERATOR,
		['?'] = HTTP_CTYPE_SEPERATOR,
		['='] = HTTP_CTYPE_SEPERATOR,
		['{'] = HTTP_CTYPE_SEPERATOR,
		['}'] = HTTP_CTYPE_SEPERATOR,
		[' '] = HTTP_CTYPE_SEPERATOR,
		['\t'] = HTTP_CTYPE_SEPERATOR
	};

static IRI
	*http_proxy,
	*https_proxy;

int http_isseperator(char c)
{
	// return strchr("()<>@,;:\\\"/[]?={} \t", c) != NULL;
	return _http_isseperator(c);
}

// TEXT           = <any OCTET except CTLs, but including LWS>
//int http_istext(char c)
//{
//	return (c>=32 && c<=126) || c=='\r' || c=='\n' || c=='\t';
//}

// token          = 1*<any CHAR except CTLs or separators>

int http_istoken(char c)
{
	return c > 32 && c <= 126 && !_http_isseperator(c);
}

const char *http_parse_token(const char *s, const char **token)
{
	const char *p;

	for (p = s; http_istoken(*s); s++);

	*token = strndup(p, s - p);

	return s;
}

// quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
// qdtext         = <any TEXT except <">>
// quoted-pair    = "\" CHAR
// TEXT           = <any OCTET except CTLs, but including LWS>
// CTL            = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
// LWS            = [CRLF] 1*( SP | HT )

const char *http_parse_quoted_string(const char *s, const char **qstring)
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

		*qstring = strndup(p, s - p);
		if (*s == '\"') s++;
	} else
		*qstring = NULL;

	return s;
}

// generic-param  =  token [ EQUAL gen-value ]
// gen-value      =  token / host / quoted-string

const char *http_parse_param(const char *s, const char **param, const char **value)
{
	const char *p;

	*param = *value = NULL;

	while (isblank(*s)) s++;

	if (*s == ';') {
		s++;
		while (isblank(*s)) s++;
	}

	for (p = s; http_istoken(*s); s++);
	*param = strndup(p, s - p);

	while (isblank(*s)) s++;

	if (*s == '=') {
		s++;
		while (isblank(*s)) s++;
		if (*s == '\"') {
			s = http_parse_quoted_string(s, value);
		} else {
			s = http_parse_token(s, value);
		}
	} else *value = NULL;

	return s;
}

// message-header = field-name ":" [ field-value ]
// field-name     = token
// field-value    = *( field-content | LWS )
// field-content  = <the OCTETs making up the field-value
//                  and consisting of either *TEXT or combinations
//                  of token, separators, and quoted-string>

const char *http_parse_name(const char *s, const char **name)
{
	while (isblank(*s)) s++;

	s = http_parse_token(s, name);

	while (*s && *s != ':') s++;

	return *s == ':' ? s + 1 : s;
}

const char *http_parse_name_fixed(const char *s, char *name, size_t name_size)
{
	const char *endp = name + name_size - 1;

	while (isblank(*s)) s++;

	while (name < endp && http_istoken(*s))
		*name++ = *s++;
	*name = 0;

	while (*s && *s != ':') s++;

	return *s == ':' ? s + 1 : s;
}

static int NONNULL_ALL compare_param(HTTP_HEADER_PARAM *p1, HTTP_HEADER_PARAM *p2)
{
	return strcasecmp(p1->name, p2->name);
}

void http_add_param(VECTOR **params, HTTP_HEADER_PARAM *param)
{
	if (!*params) *params = vec_create(4, 4, (int(*)(const void *, const void *))compare_param);
	vec_add(*params, param, sizeof(HTTP_HEADER_PARAM));
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
const char *http_parse_link(const char *s, HTTP_LINK *link)
{
	memset(link, 0, sizeof(*link));

	while (isblank(*s)) s++;

	if (*s == '<') {
		// URI reference as of RFC 3987 (if relative, resolve as of RFC 3986)
		const char *p = s + 1;
		if ((s = strchr(p, '>')) != NULL) {
			const char *name = NULL, *value = NULL;

			link->uri = strndup(p, s - p);
			s++;

			while (isblank(*s)) s++;

			while (*s == ';') {
				s = http_parse_param(s, &name, &value);
				if (name && value) {
					if (!strcasecmp(name, "rel")) {
						if (!strcasecmp(value, "describedby"))
							link->rel = link_rel_describedby;
						else if (!strcasecmp(value, "duplicate"))
							link->rel = link_rel_duplicate;
					} else if (!strcasecmp(name, "pri")) {
						link->pri = atoi(value);
					} else if (!strcasecmp(name, "type")) {
						link->type = value;
						value = NULL;
					}
					//				http_add_param(&link->params,&param);
					while (isblank(*s)) s++;
				}

				xfree(name);
				xfree(value);
			}

			//			if (!msg->contacts) msg->contacts=vec_create(1,1,NULL);
			//			vec_add(msg->contacts,&contact,sizeof(contact));

			while (*s && !isblank(*s)) s++;
		}
	}

	return s;
}

// from RFC 3230:
// Digest = "Digest" ":" #(instance-digest)
// instance-digest = digest-algorithm "=" <encoded digest output>
// digest-algorithm = token

const char *http_parse_digest(const char *s, HTTP_DIGEST *digest)
{
	const char *p;

	memset(digest, 0, sizeof(*digest));

	while (isblank(*s)) s++;

	for (p = s; http_istoken(*s); s++);
	digest->algorithm = strndup(p, s - p);

	while (isblank(*s)) s++;

	if (*s == '=') {
		s++;
		while (isblank(*s)) s++;
		if (*s == '\"') {
			s = http_parse_quoted_string(s, &digest->encoded_digest);
		} else {
			for (p = s; *s && !isblank(*s) && *s != ',' && *s != ';'; s++);
			digest->encoded_digest = strndup(p, s - p);
		}
	}

	while (*s && !isblank(*s)) s++;

	return s;
}

const char *http_parse_location(const char *s, const char **location)
{
	const char *p;

	while (isblank(*s)) s++;

	for (p = s; *s && !isblank(*s); s++);
	*location = strndup(p, s - p);

	return s;
}

// Transfer-Encoding       = "Transfer-Encoding" ":" 1#transfer-coding
// transfer-coding         = "chunked" | transfer-extension
// transfer-extension      = token *( ";" parameter )
// parameter               = attribute "=" value
// attribute               = token
// value                   = token | quoted-string

const char *http_parse_transfer_encoding(const char *s, char *transfer_encoding)
{
	while (isblank(*s)) s++;

	if (!strcasecmp(s, "identity"))
		*transfer_encoding = transfer_encoding_identity;
	else
		*transfer_encoding = transfer_encoding_chunked;

	while (http_istoken(*s)) s++;

	return s;
}

// Content-Type   = "Content-Type" ":" media-type
// media-type     = type "/" subtype *( ";" parameter )
// type           = token
// subtype        = token
// example: Content-Type: text/html; charset=ISO-8859-4

const char *http_parse_content_type(const char *s, const char **content_type, const char **charset)
{
	HTTP_HEADER_PARAM param;
	const char *p;

	while (isblank(*s)) s++;

	for (p = s; *s && (http_istoken(*s) || *s == '/'); s++);
	if (content_type)
		*content_type = strndup(p, s - p);

	if (charset) {
		*charset = NULL;

		while (*s) {
			s=http_parse_param(s, &param.name, &param.value);
			if (!null_strcasecmp("charset", param.name)) {
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

// Content-Encoding  = "Content-Encoding" ":" 1#content-coding

const char *http_parse_content_encoding(const char *s, char *content_encoding)
{
	while (isblank(*s)) s++;

	if (!strcasecmp(s, "gzip") || !strcasecmp(s, "x-gzip"))
		*content_encoding = content_encoding_gzip;
	else
		*content_encoding = content_encoding_identity;

	while (http_istoken(*s)) s++;

	return s;
}

const char *http_parse_connection(const char *s, char *keep_alive)
{
	while (isblank(*s)) s++;

	if (!strcasecmp(s, "keep-alive"))
		*keep_alive = 1;
	else
		*keep_alive = 0;

	while (http_istoken(*s)) s++;

	return s;
}

// returns GMT/UTC time as an integer of format YYYYMMDDHHMMSS
// this makes us independant from size of time_t - work around possible year 2038 problems
/*
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
		err_printf(_("Failed to parse date '%s'\n"), s);
		return 0; // return as session cookie
	}

	if (*mname) {
		for (it = 0; it < countof(mnames); it++) {
			if (!strcasecmp(mname, mnames[it])) {
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
		err_printf(_("Failed to parse date '%s'\n"), s);
		return 0; // return as session cookie
	}

	return(((((long long)year*100 + mon)*100 + day)*100 + hour)*100 + min)*100 + sec;
}
*/

// copied this routine from
// http://ftp.netbsd.org/pub/pkgsrc/current/pkgsrc/pkgtools/libnbcompat/files/timegm.c

static int leap_days(int y1, int y2)
{
	y1--;
	y2--;
	return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

static time_t NONNULL_ALL parse_rfc1123_date(const char *s)
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

	if (sscanf(s, " %*[a-zA-Z], %02d %3s %4d %2d:%2d:%2d", &day, mname, &year, &hour, &min, &sec) >= 6) {
		// RFC 822 / 1123: Wed, 09 Jun 2021 10:18:14 GMT
	}
	else if (sscanf(s, " %*[a-zA-Z], %2d-%3s-%4d %2d:%2d:%2d", &day, mname, &year, &hour, &min, &sec) >= 6) {
		// RFC 850 / 1036 or Netscape: Wednesday, 09-Jun-21 10:18:14 or Wed, 09-Jun-2021 10:18:14
	}
	else if (sscanf(s, " %*[a-zA-Z] %3s %2d %2d:%2d:%2d %4d", mname, &day, &hour, &min, &sec, &year) >= 6) {
		// ANSI C's asctime(): Wed Jun 09 10:18:14 2021
	} else {
		err_printf(_("Failed to parse date '%s'\n"), s);
		return 0; // return as session cookie
	}

	if (*mname) {
		unsigned it;

		for (it = 0; it < countof(mnames); it++) {
			if (!strcasecmp(mname, mnames[it])) {
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
		err_printf(_("Failed to parse date '%s'\n"), s);
		return 0; // return as session cookie
	}

	// calculate time_t from GMT/UTC time values

	days = 365 * (year - 1970) + leap_days(1970, year);
	days += sum_of_days[mon - 1] + (mon > 2 && leap_year);
	days += day - 1;

	return (((time_t)days * 24 + hour) * 60 + min) * 60 + sec;
}

char *http_print_date(time_t t, char *buf, size_t bufsize)
{
	static const char *dnames[7] = {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
	};
	static const char *mnames[12] = {
		"Jan", "Feb", "Mar","Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	struct tm tm;

	if (!bufsize)
		return buf;

	if (gmtime_r(&t, &tm)) {
		snprintf(buf, bufsize, "%s, %02d %s %d %02d:%02d:%02d GMT",
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

static long long get_current_time(void)
{
	time_t t = time(NULL);
	struct tm tm;

	gmtime_r(&t, &tm);

	return (((((long long)(tm.tm_year + 1900)*100 + tm.tm_mon + 1)*100 + tm.tm_mday)*100 + tm.tm_hour)*100 + tm.tm_min)*100 + tm.tm_sec;
}
*/

const char *http_parse_setcookie(const char *s, HTTP_COOKIE *cookie)
{
	const char *name, *p;

	cookie_init_cookie(cookie);

	while (isspace(*s)) s++;
	s = http_parse_token(s, &cookie->name);
	while (isspace(*s)) s++;

	if (cookie->name && *cookie->name && *s == '=') {
		// *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
		for (s++; isspace(*s);) s++;

		if (*s == '\"')
			s++;

		// cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
		for (p = s; *s > 32 && *s <= 126 && *s != '\\' && *s != ',' && *s != ';' && *s != '\"'; s++);
		cookie->value = strndup(p, s - p);

		do {
			while (*s && *s != ';') s++;
			if (!*s) break;

			for (s++; isspace(*s);) s++;
			s = http_parse_token(s, &name);

			if (name) {
				while (*s && *s != '=' && *s != ';') s++;
				// if (!*s) break;

				if (*s == '=') {
					// find end of value
					for (p = ++s; *s > 32 && *s <= 126 && *s != ';'; s++);

					if (!strcasecmp(name, "expires")) {
						cookie->expires = parse_rfc1123_date(p);
					} else if (!strcasecmp(name, "max-age")) {
						long offset = atol(p);

						if (offset > 0)
							// cookie->maxage = adjust_time(get_current_time(), offset);
							cookie->maxage = time(NULL) + offset;
						else
							cookie->maxage = 0;
					} else if (!strcasecmp(name, "domain")) {
						if (p != s) {
							if (cookie->domain)
								xfree(cookie->domain);

							if (*p == '.') { // RFC 6265 5.2.3
								do { p++; } while (*p == '.');
								cookie->domain_dot = 1;
							} else
								cookie->domain_dot = 0;

							cookie->domain = strndup(p, s - p);
						}
					} else if (!strcasecmp(name, "path")) {
						if (cookie->path)
							xfree(cookie->path);
						cookie->path = strndup(p, s - p);
					} else {
						log_printf("Unsupported cookie-av '%s'\n", name);
					}
				} else if (!strcasecmp(name, "secure")) {
					cookie->secure_only = 1;
				} else if (!strcasecmp(name, "httponly")) {
					cookie->http_only = 1;
				} else {
					log_printf("Unsupported cookie-av '%s'\n", name);
				}

				xfree(name);
			}
		} while (*s);

	} else {
		cookie_free_cookie(cookie);
		log_printf("Cookie without name or assignment ignored\n");
	}

	return s;
}

/* content of <buf> will be destroyed */

/* buf must be 0-terminated */
HTTP_RESPONSE *http_parse_response(char *buf)
{
	const char *s;
	char *line, *eol, name[32];
	HTTP_RESPONSE *resp = NULL;

	resp = xcalloc(1, sizeof(HTTP_RESPONSE));

	if (sscanf(buf, " HTTP/%3hd.%3hd %3hd %31[^\r\n] ",
		&resp->major, &resp->minor, &resp->code, resp->reason) >= 3 && (eol = strchr(buf + 10, '\n'))) {
		// eol[-1]=0;
		// log_printf("# %s\n",buf);
	} else {
		err_printf(_("HTTP response header not found\n"));
		xfree(resp);
		return NULL;
	}

	for (line = eol + 1; eol && *line && *line != '\r'; line = eol + 1) {
		eol = strchr(line + 1, '\n');
		while (eol && isblank(eol[1])) { // handle split lines
			*eol = eol[-1] = ' ';
			eol = strchr(eol + 1, '\n');
		}

		if (eol)
			eol[-1] = 0;

		// log_printf("# %p %s\n",eol,line);

		s = http_parse_name_fixed(line, name, sizeof(name));
		// s now points directly after :

		if (resp->code / 100 == 3 && !strcasecmp(name, "Location")) {
			xfree(resp->location);
			http_parse_location(s, &resp->location);
		} else if (resp->code / 100 == 3 && !strcasecmp(name, "Link")) {
			// log_printf("s=%.31s\n",s);
			HTTP_LINK link;
			http_parse_link(s, &link);
			// log_printf("link->uri=%s\n",link.uri);
			if (!resp->links)
				resp->links = vec_create(8, 8, NULL);
			vec_add(resp->links, &link, sizeof(link));
		} else if (!strcasecmp(name, "Digest")) {
			// http://tools.ietf.org/html/rfc3230
			HTTP_DIGEST digest;
			http_parse_digest(s, &digest);
			// log_printf("%s: %s\n",digest.algorithm,digest.encoded_digest);
			if (!resp->digests)
				resp->digests = vec_create(4, 4, NULL);
			vec_add(resp->digests, &digest, sizeof(digest));
		} else if (!strcasecmp(name, "Transfer-Encoding")) {
			http_parse_transfer_encoding(s, &resp->transfer_encoding);
		} else if (!strcasecmp(name, "Content-Encoding")) {
			http_parse_content_encoding(s, &resp->content_encoding);
		} else if (!strcasecmp(name, "Content-Type")) {
			http_parse_content_type(s, &resp->content_type, &resp->content_type_encoding);
		} else if (!strcasecmp(name, "Content-Length")) {
			resp->content_length = (size_t)atoll(s);
			resp->content_length_valid = 1;
		} else if (!strcasecmp(name, "Connection")) {
			http_parse_connection(s, &resp->keep_alive);
// Last-Modified: Thu, 07 Feb 2008 15:03:24 GMT
		} else if (!strcasecmp(name, "Last-Modified")) {
			resp->last_modified = parse_rfc1123_date(s);
		} else if (!strcasecmp(name, "Set-Cookie")) {
			// this is a parser. content validation must be done by higher level functions.
			HTTP_COOKIE cookie;
			http_parse_setcookie(s, &cookie);

			if (!resp->cookies)
				resp->cookies = vec_create(4, 4, NULL);
			vec_add(resp->cookies, &cookie, sizeof(cookie));
		}
	}

	// a workaround for broken server configurations
	// see http://mail-archives.apache.org/mod_mbox/httpd-dev/200207.mbox/<3D2D4E76.4010502@talex.com.pl>
	if (resp->content_encoding == content_encoding_gzip &&
		!strcasecmp(resp->content_type, "application/x-gzip"))
	{
		log_printf("Broken server configuration gzip workaround triggered\n");
		resp->content_encoding =  content_encoding_identity;
	}

	return resp;
}

int http_free_param(HTTP_HEADER_PARAM *param)
{
	xfree(param->name);
	xfree(param->value);
	return 0;
}

int http_free_link(HTTP_LINK *link)
{
	xfree(link->uri);
	xfree(link->type);
	return 0;
}

void http_free_links(VECTOR *links)
{
	vec_browse(links, (int (*)(void *))http_free_link);
	vec_free(&links);
}

int http_free_digest(HTTP_DIGEST *digest)
{
	xfree(digest->algorithm);
	xfree(digest->encoded_digest);
	return 0;
}

void http_free_digests(VECTOR *digests)
{
	vec_browse(digests, (int (*)(void *))http_free_digest);
	vec_free(&digests);
}

void http_free_cookies(VECTOR *cookies)
{
	vec_browse(cookies, (int (*)(void *))cookie_free_cookie);
	vec_free(&cookies);
}

/* for security reasons: set all freed pointers to NULL */
void http_free_response(HTTP_RESPONSE **resp)
{
	if (resp && *resp) {
		http_free_links((*resp)->links);
		(*resp)->links = NULL;
		http_free_digests((*resp)->digests);
		(*resp)->digests = NULL;
		http_free_cookies((*resp)->cookies);
		(*resp)->cookies = NULL;
		xfree((*resp)->content_type);
		xfree((*resp)->content_type_encoding);
		xfree((*resp)->location);
		// xfree((*resp)->reason);
		buffer_free(&(*resp)->header);
		buffer_free(&(*resp)->body);
		xfree(*resp);
	}
}

/* for security reasons: set all freed pointers to NULL */
void http_free_request(HTTP_REQUEST **req)
{
	if (req && *req) {
		buffer_deinit(&(*req)->esc_resource);
		buffer_deinit(&(*req)->esc_host);
		vec_free(&(*req)->lines);
		(*req)->lines = NULL;
		xfree(*req);
	}
}

HTTP_REQUEST *http_create_request(const IRI *iri, const char *method)
{
	HTTP_REQUEST *req = xcalloc(1, sizeof(HTTP_REQUEST));

	buffer_init(&req->esc_resource, req->esc_resource_buf, sizeof(req->esc_resource_buf));
	buffer_init(&req->esc_host, req->esc_host_buf, sizeof(req->esc_host_buf));

	req->scheme = iri->scheme;
	strlcpy(req->method, method, sizeof(req->method));
	iri_get_escaped_resource(iri, &req->esc_resource);
	iri_get_escaped_host(iri, &req->esc_host);
	req->lines = vec_create(8, 8, NULL);

	return req;
}

void http_add_header_vprintf(HTTP_REQUEST *req, const char *fmt, va_list args)
{
	vec_add_vprintf(req->lines, fmt, args);
}

void http_add_header_printf(HTTP_REQUEST *req, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	http_add_header_vprintf(req, fmt, args);
	va_end(args);
}

void http_add_header_line(HTTP_REQUEST *req, const char *line)
{
	vec_add_str(req->lines, line);
}

void http_add_header(HTTP_REQUEST *req, const char *name, const char *value)
{
	size_t
		lname = strlen(name),
		lvalue = strlen(value);
	char
		*buf = xmalloc(lname + 2 + lvalue + 1); // "%s: %s"

	strcpy(buf, name);
	buf[lname] = ':';
	buf[lname + 1] = ' ';
	strcpy(buf + lname + 2, value);

	vec_add_noalloc(req->lines, buf);
}

HTTP_CONNECTION *http_open(const IRI *iri)
{
	HTTP_CONNECTION
		*conn = xcalloc(1, sizeof(HTTP_CONNECTION));
	const char
		*port,
		*host;
	int
		ssl = iri->scheme == IRI_SCHEME_HTTPS;

	if (!conn)
		return NULL;

	if (iri->scheme == IRI_SCHEME_HTTP && http_proxy) {
		host = http_proxy->host;
		port = (http_proxy->port && *http_proxy->port) ? http_proxy->port : http_proxy->scheme;
	} else if (iri->scheme == IRI_SCHEME_HTTPS && https_proxy) {
		host = https_proxy->host;
		port = (https_proxy->port && *https_proxy->port) ? https_proxy->port : https_proxy->scheme;
	} else {
		host = iri->host;
		port = (iri->port && *iri->port) ? iri->port : iri->scheme;
	}

	if ((conn->ai = conn->addrinfo = tcp_resolve(host, port)) == NULL)
		goto error;

	for (; conn->ai; conn->ai = conn->ai->ai_next) {
		if ((conn->tcp = tcp_connect(conn->ai, ssl ? host : NULL)) != NULL) {
			tcp_set_timeout(conn->tcp, config.read_timeout);
			conn->esc_host = iri->host ? strdup(iri->host) : NULL;
			conn->port = iri->port ? strdup(iri->port) : NULL;
			conn->scheme = iri->scheme;
			conn->buf = buffer_alloc(102400); // reusable buffer, large enough for most requests and responses
			return conn;
		}
	}

error:
	http_close(&conn);
	return NULL;
}

void http_close(HTTP_CONNECTION **conn)
{
	if (conn && *conn) {
		tcp_close(&(*conn)->tcp);
		if (!config.dns_caching)
			freeaddrinfo((*conn)->addrinfo);
		xfree((*conn)->esc_host);
		xfree((*conn)->port);
		// xfree((*conn)->scheme);
		buffer_free(&(*conn)->buf);
		xfree(*conn);
	}
}

int http_send_request(HTTP_CONNECTION *conn, HTTP_REQUEST *req)
{
	ssize_t nbytes;

	if ((nbytes = http_request_to_buffer(req, conn->buf)) < 0) {
		err_printf(_("Failed to create request buffer\n"));
		return -1;
	}

	if (tcp_write(conn->tcp, conn->buf->data, nbytes) != nbytes) {
		err_printf(_("Failed to send %zd bytes (%d)\n"), nbytes, errno);
		return -1;
	}

	log_printf("# sent %zd bytes:\n%s", nbytes, conn->buf->data);

	return 0;
}

ssize_t http_request_to_buffer(HTTP_REQUEST *req, buffer_t *buf)
{
	int it, use_proxy = 0;

//	buffer_sprintf(buf, "%s /%s HTTP/1.1\r\nHOST: %s", req->method, req->esc_resource.data ? req->esc_resource.data : "",);

	buffer_strcpy(buf, req->method);
	buffer_memcat(buf, " ", 1);
	if (http_proxy && req->scheme == IRI_SCHEME_HTTP) {
		use_proxy = 1;
		buffer_strcat(buf, req->scheme);
		buffer_memcat(buf, "://", 3);
		buffer_bufcat(buf, &req->esc_host);
	} else if (https_proxy && req->scheme == IRI_SCHEME_HTTPS) {
		use_proxy = 1;
		buffer_strcat(buf, req->scheme);
		buffer_memcat(buf, "://", 3);
		buffer_bufcat(buf, &req->esc_host);
	}
	buffer_memcat(buf, "/", 1);
	buffer_bufcat(buf, &req->esc_resource);
	buffer_memcat(buf, " HTTP/1.1\r\n", 11);
	buffer_memcat(buf, "Host: ", 6);
	buffer_bufcat(buf, &req->esc_host);
	buffer_memcat(buf, "\r\n", 2);

	for (it = 0; it < vec_size(req->lines); it++) {
		buffer_strcat(buf, vec_get(req->lines, it));
		if (buf->data[buf->length - 1] != '\n') {
			buffer_memcat(buf, "\r\n", 2);
		}
	}

	if (use_proxy)
		buffer_strcat(buf, "Proxy-Connection: keep-alive\r\n");

	buffer_memcat(buf, "\r\n", 2);

	return buf->length;
}

HTTP_RESPONSE *http_get_response_cb(
	HTTP_CONNECTION *conn,
	HTTP_REQUEST *req,
	int (*parse_body)(void *context, const char *data, size_t length),
	void *context) // given to parse_body
{
	size_t bufsize, body_len = 0, body_size = 0;
	ssize_t nbytes, nread = 0;
	char *buf, *p = NULL;
	HTTP_RESPONSE *resp = NULL;
	DECOMPRESSOR *dc = NULL;

	// reuse generic connection buffer
	buf = conn->buf->data;
	bufsize = conn->buf->size;

	while ((nbytes = tcp_read(conn->tcp, buf + nread, bufsize - nread)) > 0) {
		log_printf("nbytes %zd nread %zd %zd\n", nbytes, nread, bufsize);
		nread += nbytes;
		buf[nread] = 0; // 0-terminate to allow string functions

		if (nread < 4) continue;

		if (nread == nbytes)
			p = buf;
		else
			p = buf + nread - nbytes - 3;

		if ((p = strstr(p, "\r\n\r\n"))) {
			// found end-of-header
			*p = 0;

			if (conn->print_response_headers)
				info_printf("# got header %zd bytes:\n%s\n\n", p - buf, buf);
			else
				log_printf("# got header %zd bytes:\n%s\n\n", p - buf, buf);

			if (req && req->save_headers) {
				buffer_t *header = buffer_init(NULL, NULL, p - buf + 2);
				buffer_memcpy(header, buf, p - buf);
				buffer_memcat(header, "\r\n\r\n", 4);

				if (!(resp = http_parse_response(buf))) {
					buffer_free(&header);
					goto cleanup; // something is wrong with the header
				}

				resp->header = header;

			} else {
				if (!(resp = http_parse_response(buf)))
					goto cleanup; // something is wrong with the header
			}

			if (req && !strcasecmp(req->method, "HEAD"))
				goto cleanup; // a HEAD response won't have a body

			p += 4; // skip \r\n\r\n to point to body
			break;
		}

		if ((size_t)nread + 1024 > bufsize) {
			buffer_ensure_capacity(conn->buf, bufsize + 1024);
			buf = conn->buf->data;
			bufsize = conn->buf->size;
		}
	}
	if (!nread) goto cleanup;

	if (!resp || resp->code / 100 == 1 || resp->code == 204 || resp->code == 304 ||
		(resp->transfer_encoding == transfer_encoding_identity && resp->content_length == 0 && resp->content_length_valid)) {
		// - body not included, see RFC 2616 4.3
		// - body empty, see RFC 2616 4.4
		goto cleanup;
	}

	dc = decompress_open(resp->content_encoding, parse_body, context);

	// calculate number of body bytes so far read
	body_len = nread - (p - buf);
	// move already read body data to buf
	memmove(buf, p, body_len);
	buf[body_len] = 0;

	if (resp->transfer_encoding != transfer_encoding_identity) {
		size_t chunk_size = 0;
		char *end;

		log_printf("method 1 %zd %zd:\n", body_len, body_size);
		// RFC 2616 3.6.1
		// Chunked-Body   = *chunk last-chunk trailer CRLF
		// chunk          = chunk-size [ chunk-extension ] CRLF chunk-data CRLF
		// chunk-size     = 1*HEX
		// last-chunk     = 1*("0") [ chunk-extension ] CRLF
		// chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
		// chunk-ext-name = token
		// chunk-ext-val  = token | quoted-string
		// chunk-data     = chunk-size(OCTET)
		// trailer        = *(entity-header CRLF)
		// entity-header  = extension-header = message-header
		// message-header = field-name ":" [ field-value ]
		// field-name     = token
		// field-value    = *( field-content | LWS )
		// field-content  = <the OCTETs making up the field-value
		//                  and consisting of either *TEXT or combinations
		//                  of token, separators, and quoted-string>

/*
			length := 0
			read chunk-size, chunk-extension (if any) and CRLF
			while (chunk-size > 0) {
				read chunk-data and CRLF
				append chunk-data to entity-body
				length := length + chunk-size
				read chunk-size and CRLF
			}
			read entity-header
			while (entity-header not empty) {
				append entity-header to existing header fields
				read entity-header
			}
			Content-Length := length
			Remove "chunked" from Transfer-Encoding
*/

		// read each chunk, stripping the chunk info
		p = buf;
		for (;;) {
			//log_printf("#1 p='%.16s'\n",p);
			// read: chunk-size [ chunk-extension ] CRLF
			while ((!(end = strchr(p, '\r')) || end[1] != '\n')) {
				if ((nbytes = tcp_read(conn->tcp, buf + body_len, bufsize - body_len)) <= 0)
					goto cleanup;

				body_len += nbytes;
				buf[body_len] = 0;
				log_printf("a nbytes %zd body_len %zd\n", nbytes, body_len);
			}
			end += 2;

			// now p points to chunk-size (hex)
			chunk_size = strtoll(p, NULL, 16);
			log_printf("chunk size is %zd\n", chunk_size);
			if (chunk_size == 0) {
				// now read 'trailer CRLF' which is '*(entity-header CRLF) CRLF'
				if (*end == '\r' && end[1] == '\n') // shortcut for the most likely case (empty trailer)
					goto cleanup;

				log_printf("reading trailer\n");
				while (!strstr(end, "\r\n\r\n")) {
					if (body_len > 3) {
						// just need to keep the last 3 bytes to avoid buffer resizing
						memmove(buf, buf + body_len - 3, 4); // plus 0 terminator, just in case
						body_len = 3;
					}
					if ((nbytes = tcp_read(conn->tcp, buf + body_len, bufsize - body_len)) <= 0)
						goto cleanup;

					body_len += nbytes;
					buf[body_len] = 0;
					end = buf;
					log_printf("a nbytes %zd\n", nbytes);
				}
				log_printf("end of trailer \n");
				goto cleanup;
			}

			p = end + chunk_size + 2;
			if (p <= buf + body_len) {
				log_printf("1 skip chunk_size %zd\n", chunk_size);
				decompress(dc, end, chunk_size);
				continue;
			}

			decompress(dc, end, (buf + body_len) - end);

			chunk_size = p - (buf + body_len); // in fact needed bytes to have chunk_size+2 in buf

			log_printf("need at least %zd more bytes\n", chunk_size);

			while (chunk_size > 0) {
				if ((nbytes = tcp_read(conn->tcp, buf, bufsize)) <= 0)
					goto cleanup;
				log_printf("a nbytes=%zd chunk_size=%zd\n", nread, chunk_size);

				if (chunk_size <= (size_t)nbytes) {
					if (chunk_size == 1 || !strncmp(buf + chunk_size - 2, "\r\n", 2)) {
						log_printf("chunk completed\n");
						// p=end+chunk_size+2;
					} else {
						err_printf(_("Expected end-of-chunk not found\n"));
						goto cleanup;
					}
					if (chunk_size > 2)
						decompress(dc, buf, chunk_size - 2);
					body_len = nbytes - chunk_size;
					if (body_len)
						memmove(buf, buf + chunk_size, body_len);
					buf[body_len] = 0;
					p = buf;
					break;
				} else {
					chunk_size -= nbytes;
					if (chunk_size >= 2)
						decompress(dc, buf, nbytes);
					else
						decompress(dc, buf, nbytes - 1); // special case: we got a partial end-of-chunk
				}
			}
		}
	} else if (resp->content_length_valid) {
		// read content_length bytes
		log_printf("method 2\n");

		if (body_len)
			decompress(dc, buf, body_len);

		while (body_len < resp->content_length && ((nbytes = tcp_read(conn->tcp, buf, bufsize)) > 0)) {
			body_len += nbytes;
			log_printf("nbytes %zd total %zd/%zd\n", nbytes, body_len, resp->content_length);
			decompress(dc, buf, nbytes);
		}
		if (nbytes < 0)
			err_printf(_("Failed to read %zd bytes (%d)\n"), nbytes, errno);
		if (body_len < resp->content_length)
			err_printf(_("Just got %zu of %zu bytes\n"), body_len, body_size);
		else if (body_len > resp->content_length)
			err_printf(_("Body too large: %zu instead of %zu bytes\n"), body_len, resp->content_length);
		resp->content_length = body_len;
	} else {
		// read as long as we can
		log_printf("method 3\n");

		if (body_len)
			decompress(dc, buf, body_len);

		while ((nbytes = tcp_read(conn->tcp, buf, bufsize)) > 0) {
			body_len += nbytes;
			log_printf("nbytes %zd total %zd\n", nbytes, body_len);
			decompress(dc, buf, nbytes);
		}
		resp->content_length = body_len;
	}

cleanup:
	decompress_close(dc);

	return resp;
}

static int _get_body(void *userdata, const char *data, size_t length)
{
	buffer_memcat((buffer_t *)userdata, data, length);

	return 0;
}

// get response, resp->body points to body in memory

HTTP_RESPONSE *http_get_response(HTTP_CONNECTION *conn, HTTP_REQUEST *req)
{
	HTTP_RESPONSE *resp;
	buffer_t *body = buffer_alloc(102400);

	resp = http_get_response_cb(conn, req, _get_body, body);

	if (resp) {
		resp->body = body;
		resp->content_length = body->length;
	} else {
		buffer_free(&body);
	}

	return resp;
}

static int _get_file(void *context, const char *data, size_t length)
{
	int fd = *(int *)context;
	ssize_t nbytes = write(fd, data, length);

	if (nbytes == -1 || (size_t)nbytes != length)
		err_printf(_("Failed to write %zu bytes of data (%d)\n"), length, errno);

	return 0;
}

HTTP_RESPONSE *http_get_response_fd(HTTP_CONNECTION *conn, int fd)
{
	HTTP_RESPONSE *resp = http_get_response_cb(conn, NULL, _get_file, &fd);

	return resp;
}

/*
// get response, resp->body points to body in memory (nested func/trampoline version)
HTTP_RESPONSE *http_get_response(HTTP_CONNECTION *conn, HTTP_REQUEST *req)
{
	size_t bodylen=0, bodysize=102400;
	char *body=xmalloc(bodysize+1);

	int get_body(char *data, size_t length)
	{
		while (bodysize<bodylen+length)
			body=xrealloc(body,(bodysize*=2)+1);

		memcpy(body+bodylen,data,length);
		bodylen+=length;
		body[bodylen]=0;
		return 0;
	}

	HTTP_RESPONSE *resp=http_get_response_cb(conn,req,get_body);

	if (resp) {
		resp->body=body;
		resp->content_length=bodylen;
	} else {
		xfree(body);
	}

	return resp;
}

HTTP_RESPONSE *http_get_response_fd(HTTP_CONNECTION *conn, int fd)
{
	int get_file(char *data, size_t length) {
		if (write(fd,data,length)!=length)
			err_printf(_("Failed to write %zu bytes of data (%d)\n"),length,errno);
		return 0;
	}

	HTTP_RESPONSE *resp=http_get_response_cb(conn,NULL,get_file);

	return resp;
}
 */

/*
HTTP_RESPONSE *http_get_response_file(HTTP_CONNECTION *conn, const char *fname)
{
	size_t bodylen=0, bodysize=102400;
	char *body=xmalloc(bodysize+1);

	int get_file(char *data, size_t length) {
		if (write(fd,data,length)!=length)
			err_printf(_("Failed to write %zu bytes of data (%d)\n"),length,errno);
		return 0;
	}

	HTTP_RESPONSE *resp=http_get_response_cb(conn,NULL,get_file);

	return resp;
}
 */

void http_set_http_proxy(const char *proxy, const char *locale)
{
	iri_free(&http_proxy);
	http_proxy = iri_parse_encoding(proxy, locale);
}

void http_set_https_proxy(const char *proxy, const char *locale)
{
	iri_free(&https_proxy);
	https_proxy = iri_parse_encoding(proxy, locale);
}

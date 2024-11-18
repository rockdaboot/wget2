/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Options and related routines
 *
 * Changelog
 * 12.06.2012  Tim Ruehsen  created
 *
 *
 * How to add a new command line option
 * ====================================
 * - extend wget_options.h/struct config with the needed variable
 * - add a default value for your variable in the 'config' initializer if needed (in this file)
 * - add the long option into 'options[]' (in this file). keep alphabetical order !
 * - if appropriate, add a new parse function (examples see below)
 * - extend the documentation (at docs/wget2.md)
 *
 * Set args to -1 if value for an option is optional.
 */

#include <config.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <c-ctype.h>
#include <errno.h>
#include <glob.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h> // LLONG_MAX, INT_MAX
#include <sys/stat.h>
#include <spawn.h>
#include "getpass.h"
#include "xgethostname.h"

#include <wget.h>

#include "wget_main.h"
#include "wget_log.h"
#include "wget_options.h"
#include "wget_dl.h"
#include "wget_plugin.h"
#include "wget_stats.h"
#include "wget_testing.h"
#include "wget_utils.h"
#include "wget_bar.h"
#ifdef WITH_GPGME
#  include "wget_gpgme.h"
#endif

static void set_allocation_functions(void);

static exit_status_e
	exit_status;

void set_exit_status(exit_status_e status)
{
	// use Wget exit status scheme:
	// - error code 0 is default
	// - error code 1 is used directly by exit() (fatal errors)
	// - error codes 2... : lower numbers precede higher numbers
	if (exit_status) {
		if (status < exit_status) {
			debug_printf("%s(%d)\n", __func__, (int) status);
			exit_status = status;
		}
	} else {
		debug_printf("%s(%d)\n", __func__, (int) status);
		exit_status = status;
	}
}

exit_status_e get_exit_status(void)
{
	return exit_status;
}

// If you add a new section here, remember to increment the value of
// SECTION_END. This must always be the last element of this enum and exactly
// one greater than the value of the element before it.
typedef enum {
	SECTION_STARTUP,
	SECTION_DOWNLOAD,
	SECTION_HTTP,
	SECTION_SSL,
	SECTION_DIRECTORY,
#ifdef WITH_GPGME
	SECTION_GPG,
#endif
	SECTION_PLUGIN,
	SECTION_END,
} help_section_t;

typedef const struct optionw *option_t; // forward declaration

struct optionw {
	const char
		long_name[22];
	void
		*var;
	int
		(*parser)(option_t opt, const char *val, const char invert);
	int
		args;
	char
		short_name;
	help_section_t
	    section;
	const char
	    *help_str[4];
};

static const char version_text[] =
"\n"
"Copyright (C) 2012-2015 Tim Ruehsen\n"
"Copyright (C) 2015-2024 Free Software Foundation, Inc.\n"
"\n"
"License GPLv3+: GNU GPL version 3 or later\n"
"<http://www.gnu.org/licenses/gpl.html>.\n"
"This is free software: you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.\n"
"\n"
"Please send bug reports and questions to <bug-wget@gnu.org>.";

static int print_version(WGET_GCC_UNUSED option_t opt, WGET_GCC_UNUSED const char *val, WGET_GCC_UNUSED const char invert)
{
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	puts("GNU Wget2 " PACKAGE_VERSION " - multithreaded metalink/file/website downloader\n");
	const char version_info[] =
	"+digest"

#if defined WITH_GNUTLS
	" +https"
	" +ssl/gnutls"
#elif defined WITH_OPENSSL
	" +https"
	" +ssl/openssl"
#elif defined WITH_WOLFSSL
	" +https"
	" +ssl/wolfssl"
#else
	" -https"
	" -ssl"
#endif

	" +ipv6"
	" +iri"

#if SIZEOF_OFF_T >= 8
	" +large-file"
#else
	" -large-file"
#endif

#if defined ENABLE_NLS
	" +nls"
#else
	" -nls"
#endif

#if defined ENABLE_NTLM
  " +ntlm"
#else
  " -ntlm"
#endif

#if defined ENABLE_OPIE
	" +opie"
#else
	" -opie"
#endif

#if defined WITH_LIBPSL
	" +psl"
#else
	" -psl"
#endif

#if defined WITH_LIBHSTS
	" +hsts\n"
#else
	" -hsts\n"
#endif

#if defined HAVE_ICONV
	"+iconv"
#else
	"-iconv"
#endif

#if defined WITH_LIBIDN2
	" +idn2"
#elif defined WITH_LIBIDN
	" +idn"
#else
	" -idn"
#endif

#if defined WITH_ZLIB
	" +zlib"
#else
	" -zlib"
#endif

#if defined WITH_LZMA
	" +lzma"
#else
	" -lzma"
#endif

#if defined WITH_BROTLIDEC
	" +brotlidec"
#else
	" -brotlidec"
#endif

#if defined WITH_ZSTD
	" +zstd"
#else
	" -zstd"
#endif

#if defined WITH_BZIP2
	" +bzip2"
#else
	" -bzip2"
#endif

#if defined WITH_LZIP
	" +lzip"
#else
	" -lzip"
#endif

#if defined WITH_LIBNGHTTP2
	" +http2"
#else
	" -http2"
#endif

#if defined WITH_GPGME
	" +gpgme"
#else
	" -gpgme"
#endif
	;

	puts(version_info);
	puts(version_text);

#endif // #ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

	set_exit_status(EXIT_STATUS_NO_ERROR);
	return -1; // stop processing & exit
}

static int parse_integer(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	*((int *)opt->var) = val ? atoi(val) : 0;

	return 0;
}

static int parse_uint16(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	int port = val ? atoi(val) : 0;

	if (port >= 0 && port <= UINT16_MAX) {
		*((uint16_t *)opt->var) = (uint16_t) port;
		return 0;
	}

	error_printf(_("Value out of range (0-65535): %s\n"), val);
	return -1;
}

// parse '2.5k' locale independent
static int parse_double_modifier(const char *in, double *d, char *c)
{
	bool minus = false;

	while (c_isspace(*in))
		in++;

	if (*in == '+') {
		in++;
	} else if (*in == '-') {
		in++;
		minus = true;
	}

	if (!c_isdigit(*in))
		return 0;

	for (*d = 0; c_isdigit(*in); in++)
		*d = *d * 10 + (*in - '0');

	if (*in == '.') {
		in++;
		for (double q = 10; c_isdigit(*in); q *= 10, in++)
			*d += (*in - '0') / q;
	}

	if (minus)
		*d = -*d;

	*c = *in;

	return *c ? 2 : 1;
}

static int parse_numbytes(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (val) {
		char modifier = 0, error = 0;
		double num = 0;

		if (!wget_strcasecmp_ascii(val, "INF") || !wget_strcasecmp_ascii(val, "INFINITY")) {
			*((long long *)opt->var) = 0;
			return 0;
		}

		if (parse_double_modifier(val, &num, &modifier) >= 1 && num >= 0) {
			if (modifier) {
				switch (c_tolower(modifier)) {
				case 'k': num *= 1024; break;
				case 'm': num *= 1024*1024; break;
				case 'g': num *= 1024*1024*1024; break;
				case 't': num *= 1024*1024*1024*1024LL; break;
				default: error = 1;
				}
			}
		} else
			error = 1;

		if (error) {
			error_printf(_("Invalid byte specifier: %s\n"), val);
			return -1;
		}

		*((long long *)opt->var) = num > LLONG_MAX ? LLONG_MAX : (long long) num;
	}

	return 0;
}

static int parse_filename(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	xfree(*((const char **)opt->var));
	*((const char **)opt->var) = val ? shell_expand(val) : NULL;

	debug_printf("Expanded value = %s\n", *(const char **)opt->var);
	return 0;
}

static int parse_string(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	// the strdup'ed string will be released on program exit
	xfree(*((const char **)opt->var));
	*((const char **)opt->var) = wget_strdup(val);

	return 0;
}

static int parse_stringset(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	wget_stringmap *map = *((wget_stringmap **)opt->var);

	if (val) {
		const char *s, *p;

		wget_stringmap_clear(map);

		for (s = p = val; *p; s = p + 1) {
			if ((p = strchrnul(s, ',')) != s)
				wget_stringmap_put(map, wget_strmemdup(s, p - s), NULL);
		}
	} else {
		wget_stringmap_clear(map);
	}

	return 0;
}

static int compare_wget_http_param(wget_http_header_param *a, wget_http_header_param *b)
{
	if (wget_strcasecmp_ascii(a->name, b->name) == 0)
		if (wget_strcasecmp_ascii(a->value, b->value) == 0)
			return 0;
	return 1;
}

static int parse_header(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	wget_vector *v = *((wget_vector **)opt->var);

	if (val && *val) {
		char *value, *delim_pos;

		if (!v) {
			v = *((wget_vector **)opt->var) =
				wget_vector_create(8, (wget_vector_compare_fn *) compare_wget_http_param);
			wget_vector_set_destructor(v, (wget_vector_destructor *) wget_http_free_param);
		}

		delim_pos = strchr(val, ':');

		if (!delim_pos || delim_pos == val) {
			wget_error_printf(_("Ignoring invalid header: %s\n"), val);
			return 0;
		}

		value = delim_pos + 1;
		while (*value == ' ')
			value++;

		if (*value == '\0') {
			wget_error_printf(_("No value in header (ignoring): %s\n"), val);
			return 0;
		}

		wget_http_header_param *param = wget_malloc(sizeof(wget_http_header_param));
		param->name = wget_strmemdup(val, delim_pos - val);
		param->value = wget_strdup(value);

		if (wget_vector_find(v, param) < 0)
			wget_vector_add(v, param);
		else
			wget_http_free_param(param);

	} else if (val && *val == '\0') {
		wget_vector_clear(v);
		return 0;
	}

	return 0;
}

static const char *strchrnul_esc(const char *s, char c)
{
	const char *p;

	for (p = s; *p; p++) {
		if (*p == '\\' && (p[1] == '\\' || p[1] == c))
			p++;
		else if (*p == c)
			return p;
	}

	return p; // pointer to trailing \0
}

static char *strmemdup_esc(const char *s, size_t size)
{
   const char *p, *e;
	size_t newsize = 0;

	for (p = s, e = s + size; p < e; p++) {
		if (*p == '\\') {
			if (p < e - 1) {
				newsize++;
				p++;
			}
		} else
			newsize++;
	}

	char *ret = wget_malloc(newsize + 1);
	char *dst = ret;

	for (p = s, e = s + size; p < e; p++) {
		if (*p == '\\') {
			if (p < e - 1)
				*dst++ = *++p;
		} else
			*dst++ = *p;
	}
	*dst = 0;

	return ret;
}

static int parse_stringlist_expand(option_t opt, const char *val, int expand, int max_entries)
{
	if (val && *val) {
		wget_vector *v = *((wget_vector **)opt->var);
		const char *s, *p;

		if (!v)
			v = *((wget_vector **)opt->var) = wget_vector_create(8, (wget_vector_compare_fn *) strcmp);

		for (s = p = val; *p; s = p + 1) {
			if ((p = strchrnul_esc(s, ',')) != s) {
				if (wget_vector_size(v) >= max_entries) {
					wget_debug_printf("%s: More than %d entries, ignoring overflow\n", __func__, max_entries);
					return -1;
				}

				const char *fname = strmemdup_esc(s, p - s);

				if (expand && *s == '~') {
					wget_vector_add(v, shell_expand(fname));
					xfree(fname);
				} else
					wget_vector_add(v, fname);
			}
		}
	} else {
		wget_vector_free(opt->var);
	}

	return 0;
}

static int parse_stringlist(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	/* max number of 1024 entries to avoid out-of-memory */
	return parse_stringlist_expand(opt, val, 0, 1024);
}

static char *set_char_prefix(const char *val, char prefix)
{
	if (val && *val) {
		// we just need a scratch buffer, no need for optimal size calculation
		char *prefixed_val = wget_malloc(strlen(val) * 3 + 1), *dst = prefixed_val;

		*dst++ = prefix;
		for (const char *src = val; *src; src++) {
			if (*src == '\\') {
				*dst++ = *src;
				if (src[1])
					*dst++ = *++src;
			} else if (*src == ',') {
				while (dst[-1] == '/')
					dst--;
				*dst++ = *src;
				*dst++ = prefix;
			} else
				*dst++ = *src;
		}

		while (dst[-1] == '/')
			dst--;

		*dst = 0;

		return prefixed_val;
	}

	return NULL;
}

static int parse_included_directories(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	char *prefixed_val = set_char_prefix(val, INCLUDED_DIRECTORY_PREFIX);
	int ret = parse_stringlist_expand(opt, prefixed_val, 0, 1024);

	if (prefixed_val)
		xfree(prefixed_val);

	return ret;
}

static int parse_excluded_directories(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	char *prefixed_val = set_char_prefix(val, EXCLUDED_DIRECTORY_PREFIX);
	int ret = parse_stringlist_expand(opt, prefixed_val, 0, 1024);

	if (prefixed_val)
		xfree(prefixed_val);

	return ret;
}

static int parse_filenames(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	/* max number of 32 files to avoid out-of-memory by recursion */
	return parse_stringlist_expand(opt, val, 1, 32);
}

static void tag_free(void *tag)
{
	wget_html_tag *t = tag;

	if (t) {
		xfree(t->attribute);
		xfree(t->name);
		xfree(t);
	}
}

static void WGET_GCC_NONNULL_ALL add_tag(wget_vector *v, const char *begin, const char *end)
{
	wget_html_tag *tag = wget_malloc(sizeof(wget_html_tag));
	const char *attribute;

	if ((attribute = memchr(begin, '/', end - begin))) {
		tag->name = wget_strmemdup(begin, attribute - begin);
		tag->attribute = wget_strmemdup(attribute + 1, (end - begin) - (attribute - begin) - 1);
	} else {
		tag->name = wget_strmemdup(begin, end - begin);
		tag->attribute = NULL;
	}

	if (wget_vector_find(v, tag) < 0)
		wget_vector_insert_sorted(v, tag);
	else
		tag_free(tag); // avoid double entries
}

static int WGET_GCC_NONNULL_ALL compare_tag(const wget_html_tag *t1, const wget_html_tag *t2)
{
	int n;

	if (!(n = wget_strcasecmp_ascii(t1->name, t2->name))) {
		if (!t1->attribute) {
			if (!t2->attribute)
				n = 0;
			else
				n = -1;
		} else if (!t2->attribute) {
			n = 1;
		} else
			n = wget_strcasecmp_ascii(t1->attribute, t2->attribute);
	}

	return n;
}

static int parse_taglist(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (val && *val) {
		wget_vector *v = *((wget_vector **)opt->var);
		const char *s, *p;

		if (!v) {
			v = *((wget_vector **)opt->var) = wget_vector_create(8, (wget_vector_compare_fn *) compare_tag);
			wget_vector_set_destructor(v, tag_free);
		}

		for (s = p = val; *p; s = p + 1) {
			if ((p = strchrnul(s, ',')) != s)
				add_tag(v, s, p);
		}
	} else {
		wget_vector_free(opt->var);
	}

	return 0;
}

static int parse_check_certificate(option_t opt, const char *val, const char invert)
{
	if (opt->var) {
		if (!val || !strcmp(val, "1") || !wget_strcasecmp_ascii(val, "y") || !wget_strcasecmp_ascii(val, "yes") || !wget_strcasecmp_ascii(val, "on"))
			*((check_certificate_mode *) opt->var) = !invert ? CHECK_CERTIFICATE_ENABLED : CHECK_CERTIFICATE_DISABLED;
		else if (!*val || !strcmp(val, "0") || !wget_strcasecmp_ascii(val, "n") || !wget_strcasecmp_ascii(val, "no") || !wget_strcasecmp_ascii(val, "off"))
			*((check_certificate_mode *) opt->var) = invert ? CHECK_CERTIFICATE_ENABLED : CHECK_CERTIFICATE_DISABLED;
		else if (!strcmp(val, "quiet"))
			*((check_certificate_mode *) opt->var) = CHECK_CERTIFICATE_LOG_DISABLED;
		else {
			error_printf(_("Invalid value '%s'\n"), val);
			return -1;
		}
	}

	return 0;
}

static int parse_bool(option_t opt, const char *val, const char invert)
{
	if (opt->var) {
		if (!val || !strcmp(val, "1") || !wget_strcasecmp_ascii(val, "y") || !wget_strcasecmp_ascii(val, "yes") || !wget_strcasecmp_ascii(val, "on"))
			*((char *) opt->var) = !invert;
		else if (!*val || !strcmp(val, "0") || !wget_strcasecmp_ascii(val, "n") || !wget_strcasecmp_ascii(val, "no") || !wget_strcasecmp_ascii(val, "off"))
			*((char *) opt->var) = invert;
		else {
			error_printf(_("Invalid boolean value '%s'\n"), val);
			return -1;
		}
	}

	return 0;
}

static int parse_mirror(option_t opt, const char *val, const char invert)
{
	int rc;

	if ((rc = parse_bool(opt, val, invert)) < 0)
		return rc;

	if (config.mirror) {
		config.recursive = 1;
		config.level = 0; // INF
		config.timestamping = 1;
	} else {
		config.recursive = 0;
		config.level = 5; // default value
		config.timestamping = 0;
	}

	return 0;
}

static int parse_timeout(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	double fval = -1;

	if (wget_strcasecmp_ascii(val, "INF") && wget_strcasecmp_ascii(val, "INFINITY")) {
		char modifier = 0;

		if (parse_double_modifier(val, &fval, &modifier) >= 1 && fval >= 0) {
			if (modifier) {
				switch (c_tolower(modifier)) {
				case 's': fval *= 1000; break;
				case 'm': fval *= 60 * 1000; break;
				case 'h': fval *= 60 * 60 * 1000; break;
				case 'd': fval *= 60 * 60 * 24 * 1000; break;
				default: error_printf(_("Invalid time specifier in '%s'\n"), val); return -1;
				}
			} else
				fval *= 1000;
		}
	}

	if (fval <= 0) // special Wget compatibility: timeout 0 means INFINITY
		fval = -1;

	if (opt->var) {
		*((int *)opt->var) = fval > INT_MAX ? INT_MAX : (int) fval;
		// debug_printf("timeout set to %gs\n",*((int *)opt->var)/1000.);
	} else {
		// --timeout option sets all timeouts
		config.connect_timeout =
		config.dns_timeout =
		config.read_timeout = fval > INT_MAX ? INT_MAX : (int) fval;
	}

	return 0;
}

static int WGET_GCC_PURE WGET_GCC_NONNULL((1)) parse_cert_type(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (!val || !wget_strcasecmp_ascii(val, "PEM"))
		*((char *)opt->var) = WGET_SSL_X509_FMT_PEM;
	else if (!wget_strcasecmp_ascii(val, "DER") || !wget_strcasecmp_ascii(val, "ASN1"))
		*((char *)opt->var) = WGET_SSL_X509_FMT_DER;
	else {
		error_printf(_("Unknown cert type '%s'\n"), val);
		return -1;
	}

	return 0;
}

static int WGET_GCC_PURE WGET_GCC_NONNULL((1)) parse_regex_type(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (!val || !wget_strcasecmp_ascii(val, "posix"))
		*((char *)opt->var) = WGET_REGEX_TYPE_POSIX;

#if defined WITH_LIBPCRE2 || defined WITH_LIBPCRE
	else if (!wget_strcasecmp_ascii(val, "pcre"))
		*((char *)opt->var) = WGET_REGEX_TYPE_PCRE;
#endif
	else {
		error_printf(_("Unsupported regex type '%s'\n"), val);
		return -1;
	}

	return 0;
}

static int WGET_GCC_PURE WGET_GCC_NONNULL((1)) parse_progress_type(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (!val || !*val) {
		error_printf(_("Empty progress type\n"));
		return -1;
	}

	if (!wget_strcasecmp_ascii(val, "none"))
		*((char *)opt->var) = PROGRESS_TYPE_NONE;
	else if (!wget_strncasecmp_ascii(val, "bar", 3) && (val[3] == ':' || val[3] == 0)) {
		*((char *)opt->var) = PROGRESS_TYPE_BAR;
		// Silent Wget compatibility
		if (!wget_strncasecmp_ascii(val+4, "force", 5) || !wget_strncasecmp_ascii(val+4, "noscroll:force", 14)) {
			config.force_progress = true;
		}
	} else if (!wget_strncasecmp_ascii(val, "dot", 3) && (val[3] == ':' || val[3] == 0)) {
		// Wget compatibility, whether want to support 'dot' depends on user feedback.
		info_printf(_("Progress type '%s' ignored. It is not implemented yet\n"), val);
	} else {
		error_printf(_("Unknown progress type '%s'\n"), val);
		return -1;
	}

	return 0;
}

// legacy option, needed to succeed test suite
static int WGET_GCC_PURE WGET_GCC_NONNULL((1)) parse_restrict_names(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	int flags = WGET_RESTRICT_NAMES_NONE;

	if (!val || !*val) {
		error_printf(_("Missing restrict-file-name type\n"));
		goto error;
	}

	// Reset restrictions to default
	if (!wget_strcasecmp_ascii(val, "none")) {
		*((int *)opt->var) = WGET_RESTRICT_NAMES_NONE;
		return 0;
	}

	const char *s, *p;
	for (s = p = val; *p; s = p + 1) {
		if ((p = strchrnul(s, ',')) == s)
			continue;

		size_t len = p - s;

		if (!wget_strncasecmp_ascii(s, "unix", len))
			flags |= WGET_RESTRICT_NAMES_UNIX;
		else if (!wget_strncasecmp_ascii(s, "windows", len))
			flags |= WGET_RESTRICT_NAMES_WINDOWS;
		else if (!wget_strncasecmp_ascii(s, "nocontrol", len))
			flags |= WGET_RESTRICT_NAMES_NOCONTROL;
		else if (!wget_strncasecmp_ascii(s, "ascii", len))
			flags |= WGET_RESTRICT_NAMES_ASCII;
		else if (!wget_strncasecmp_ascii(s, "uppercase", len))
			flags |= WGET_RESTRICT_NAMES_UPPERCASE;
		else if (!wget_strncasecmp_ascii(s, "lowercase", len))
			flags |= WGET_RESTRICT_NAMES_LOWERCASE;
		else {
			error_printf(_("Unknown restrict-file-name type '%s'\n"), val);
			goto error;
		}
	}

	if ((flags & WGET_RESTRICT_NAMES_UNIX) && (flags & WGET_RESTRICT_NAMES_WINDOWS)) {
		error_printf(_("Restrict file names to either 'unix' or 'windows'\n"));
		goto error;
	}

	if ((flags & WGET_RESTRICT_NAMES_UPPERCASE) && (flags & WGET_RESTRICT_NAMES_LOWERCASE)) {
		error_printf(_("Restrict file names to either 'uppercase' or 'lowercase'\n"));
		goto error;
	}

	*((int *)opt->var) = flags;

	return 0;

error:
	error_printf(_("    use [none]|[unix|windows],[lowercase|uppercase],[nocontrol][,ascii].\n"));
	return -1;
}

// Wget compatibility: support -nv, -nc, -nd, -nH and -np
// Wget supports --no-... to all boolean and string options
static int parse_n_option(WGET_GCC_UNUSED option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (val) {
		const char *p;

		for (p = val; *p; p++) {
			switch (*p) {
			case 'v':
				config.verbose = 0;
				break;
			case 'c':
				config.clobber = 0;
				break;
			case 'd':
				config.directories = 0;
				break;
			case 'H':
				config.host_directories = 0;
				break;
			case 'p':
				config.parent = 0;
				break;
			default:
				error_printf(_("Unknown option '-n%c'\n"), *p);
				return -1;
			}

			debug_printf("name=-n%c value=0\n", *p);
		}
	}

	return 0;
}

static int parse_prefer_family(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (!val || !wget_strcasecmp_ascii(val, "none"))
		*((int *)opt->var) = WGET_NET_FAMILY_ANY;
	else if (!wget_strcasecmp_ascii(val, "ipv4"))
		*((int *)opt->var) = WGET_NET_FAMILY_IPV4;
	else if (!wget_strcasecmp_ascii(val, "ipv6"))
		*((int *)opt->var) = WGET_NET_FAMILY_IPV6;
	else {
		error_printf(_("Unknown address family '%s'\n"), val);
		return -1;
	}

	return 0;
}

static int parse_stats(option_t opt, const char *val, const char invert)
{
	const char *p;
	wget_stats_format format;

	stats_args **stats = (stats_args **) opt->var;
	if (*stats)
		xfree((*stats)->filename);

	if (invert) {
		xfree(*stats);
		return 0;
	}

	if (val && (p = strchr(val, ':'))) {
		if (!wget_strncasecmp_ascii("human", val, p - val) || !wget_strncasecmp_ascii("h", val, p - val))
			format = WGET_STATS_FORMAT_HUMAN;
		else if (!wget_strncasecmp_ascii("csv", val, p - val))
			format = WGET_STATS_FORMAT_CSV;
		else {
			error_printf(_("Unknown stats format '%s'\n"), val);
			return -1;
		}

		val = p + 1;
	} else { // no format given
		format = WGET_STATS_FORMAT_HUMAN;
	}

	if (!*stats)
		*stats = wget_calloc(1, sizeof(stats_args));

	(*stats)->filename = shell_expand(val);
	(*stats)->format = format;

	return 0;
}

static int plugin_loading_enabled = 0;

static int parse_plugin(WGET_GCC_UNUSED option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	dl_error_t e[1];

	if (! plugin_loading_enabled)
		return 0;

	dl_error_init(e);

	if (! plugin_db_load_from_name(val, e)) {
		error_printf(_("Plugin '%s' failed to load: %s\n"), val, dl_error_get_msg(e));
		dl_error_set(e, NULL);
		return -1;
	}

	return 0;
}

static int parse_plugin_local(WGET_GCC_UNUSED option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	dl_error_t e[1];

	if (! plugin_loading_enabled)
		return 0;

	dl_error_init(e);

	if (! plugin_db_load_from_path(val, e)) {
		error_printf(_("Plugin '%s' failed to load: %s\n"), val, dl_error_get_msg(e));
		dl_error_set(e, NULL);
		return -1;
	}

	return 0;
}

static int parse_plugin_dirs(WGET_GCC_UNUSED option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (! plugin_loading_enabled)
		return 0;

	plugin_db_clear_search_paths();
	plugin_db_add_search_paths(val, ',');

	return 0;
}

static int parse_plugin_option
	(WGET_GCC_UNUSED option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	dl_error_t e[1];

	if (! plugin_loading_enabled)
		return 0;

	dl_error_init(e);

	if (plugin_db_forward_option(val, e) < 0) {
		error_printf("%s\n", dl_error_get_msg(e)); // no translation
		dl_error_set(e, NULL);
		return -1;
	}

	return 0;
}

static int parse_local_db(option_t opt, const char *val, const char invert)
{
	int rc;

	if ((rc = parse_bool(opt, val, invert)) < 0)
		return rc;

	config.cookies =
	config.hsts =
	config.hpkp =
	config.ocsp =
	config.tls_resume = config.local_db;

	return 0;
}

static int parse_report_speed_type(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (!wget_strcasecmp_ascii(val, "bytes"))
		*((wget_report_speed *)opt->var) = WGET_REPORT_SPEED_BYTES;
	else if (!wget_strcasecmp_ascii(val, "bits"))
		*((wget_report_speed *)opt->var) = WGET_REPORT_SPEED_BITS;
	else if (!val[0]) {
		error_printf(_("Missing required type specifier\n"));
		return -1;
	}
	else {
		error_printf(_("Invalid type specifier: %s\n"), val);
		return -1;
	}

	return 0;
}

static int parse_https_enforce(option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	if (!wget_strcasecmp_ascii(val, "hard"))
		*((https_enforce_mode *)opt->var) = HTTPS_ENFORCE_HARD;
	else if (!wget_strcasecmp_ascii(val, "soft"))
		*((https_enforce_mode *)opt->var) = HTTPS_ENFORCE_SOFT;
	else if (!wget_strcasecmp_ascii(val, "none"))
		*((https_enforce_mode *)opt->var) = HTTPS_ENFORCE_NONE;
	else if (!val[0]) {
		error_printf(_("Missing required type specifier\n"));
		return -1;
	}
	else {
		error_printf(_("Invalid type specifier: %s\n"), val);
		return -1;
	}

	return 0;
}

#ifdef WITH_GPGME
static int parse_verify_sig(option_t opt, const char *val, const char invert)
{
	if (opt->var) {
		if (invert) {
			if (val) {
				error_printf(_("no-verify-sig cannot take additional arguments\n"));
				return -1;
			} else {
				*((gpg_verify_mode *)opt->var) = GPG_VERIFY_DISABLED;
			}
		} else if (!val || !wget_strcasecmp_ascii(val, "fail"))
			*((gpg_verify_mode *)opt->var) = GPG_VERIFY_SIG_FAIL;
		else if (!wget_strcasecmp_ascii(val, "no-fail"))
			*((gpg_verify_mode *)opt->var) = WGET_GPG_VERIFY_SIG_NO_FAIL;
		else {
			error_printf(_("Invalid option specifier: %s\n"), val);
			return -1;
		}
	}

	return 0;
}
#endif

static int parse_compression(option_t opt, const char *val, const char invert)
{
	wget_vector *v = *((wget_vector **)opt->var);

	if (!val && invert) {   // --no-compression
		// should free the previous TYPE list and clear config.compression_methods for override
		if (v) {
			wget_vector_free((wget_vector **)opt->var);
			config.compression_methods[wget_content_encoding_max] = 0;
		}

		config.no_compression = true;
		return 0;
	} else if (val && !invert) {    // --compression=TYPE
		int rc;

		// should free the previous TYPE list and clear config.compression_methods for override
		if (v) {
			wget_vector_free((wget_vector **)opt->var);
			config.compression_methods[wget_content_encoding_max] = 0;
		}

		if ((rc = parse_stringlist_expand(opt, val, 0, 16)))
			return rc;

		v = *((wget_vector **)opt->var);

		config.no_compression = false;
		long long methods_bits = 0;		// check duplication

		for (int it = 0; it < wget_vector_size(v); it++) {
			int not_built = 0;
			const char *name = wget_vector_get(v, it);
			wget_content_encoding type = wget_content_encoding_by_name(name);

			if (type == wget_content_encoding_unknown) {
				wget_error_printf(_("Compression type '%s' not supported\n"), name);
				return -1;
			} else if (methods_bits & (1 << type)) {
				wget_error_printf(_("Duplicate type '%s'"), name);
				return -1;
			}

#ifndef WITH_ZLIB
			if (type == wget_content_encoding_gzip || type == wget_content_encoding_deflate)
				not_built = 1;
#endif
#ifndef WITH_BZIP2
			if (type == wget_content_encoding_bzip2)
				not_built = 1;
#endif
#ifndef WITH_LZMA
			if (type == wget_content_encoding_xz || type == wget_content_encoding_lzma)
				not_built = 1;
#endif
#ifndef WITH_BROTLIDEC
			if (type == wget_content_encoding_brotli)
				not_built = 1;
#endif
#ifndef WITH_ZSTD
			if (type == wget_content_encoding_zstd)
				not_built = 1;
#endif
#ifndef WITH_LZIP
			if (type == wget_content_encoding_lzip)
				not_built = 1;
#endif

			if (not_built) {
				wget_error_printf(_("Lib for type %s not built"), wget_content_encoding_to_name(type));
				return -1;
			}

			methods_bits |= (1 << type);
			config.compression_methods[config.compression_methods[wget_content_encoding_max]++] = type;
		}

		return 0;
	} else if (!val && !invert) {   // --compression (for override)
		config.no_compression = false;
		return 0;
	}

	return -1;
}

static int parse_download_attr(option_t opt, const char *val, const char invert)
{
	(void) opt;

	if (!val && invert) {   // --no-download-attr
		config.download_attr = DOWNLOAD_ATTR_NO;
		return 0;
	}

	if (!val) {    // --download_attr
		config.download_attr = DOWNLOAD_ATTR_STRIPPATH;
		return 0;
	}

	if (invert) {
		error_printf(_("Disallowed Value for --no-download-attr: %s\n"), val);
		return -1;
	}

	if (!strcasecmp(val, "strippath")) {
		config.download_attr = DOWNLOAD_ATTR_STRIPPATH;
	} else if (!strcasecmp(val, "usepath")) {
		config.download_attr = DOWNLOAD_ATTR_USEPATH;
	} else {
		error_printf(_("Invalid value for --download-attr: %s\n"), val);
		return -1;
	}

	return 0;
}

static int list_plugins(WGET_GCC_UNUSED option_t opt,
	WGET_GCC_UNUSED const char *val, WGET_GCC_UNUSED const char invert)
{
	if (! plugin_loading_enabled)
		return 0;

	wget_vector *v = wget_vector_create(16, NULL);
	plugin_db_list(v);

	int n_names = wget_vector_size(v);
	for (int i = 0; i < n_names; i++) {
		const char *name = (const char *) wget_vector_get(v, i);
		printf("%s\n", name);
	}
	wget_vector_free(&v);

	set_exit_status(EXIT_STATUS_NO_ERROR);
	return -1; // stop processing & exit
}

static int print_plugin_help(WGET_GCC_UNUSED option_t opt,
	WGET_GCC_UNUSED const char *val, WGET_GCC_UNUSED const char invert)
{
	if (! plugin_loading_enabled)
		return 0;

	plugin_db_show_help();

	set_exit_status(EXIT_STATUS_NO_ERROR);
	return -1; // stop processing & exit
}

// default values for config options (if not 0 or NULL)
// WARNING: any constant string used here must be allocated in init as we may call xfree on them later
struct config config = {
	.auth_no_challenge = false,
	.connect_timeout = -1,
	.dns_timeout = -1,
	.read_timeout = 900 * 1000, // 900s
	.max_redirect = 20,
	.max_threads = 5,
	.dns_caching = 1,
	// we use 'Wget' here for compatibility, see https://github.com/rockdaboot/wget2/issues/314
	.user_agent = "Wget/"PACKAGE_VERSION,
	.verbose = 1,
	.check_certificate= CHECK_CERTIFICATE_ENABLED,
	.check_hostname=1,
	.cert_type = WGET_SSL_X509_FMT_PEM,
	.private_key_type = WGET_SSL_X509_FMT_PEM,
	.secure_protocol = "AUTO",
	.ca_directory = "system",
	.ca_cert = "system",
	.cookies = 1,
	.keep_alive = 1,
	.use_server_timestamps = 1,
	.directories = 1,
	.host_directories = 1,
	.cache = 1,
	.clobber = 1,
	.default_page = "index.html",
	.level = 5,
	.parent = 1,
	.robots = 1,
	.tries = 20,
	.hsts = 1,
	.hsts_preload = 1,
	.hpkp = 1,
	.system_config = SYSCONFDIR"wget2rc",

#if defined WITH_LIBNGHTTP2
	.http2 = 1,
	.http2_request_window = 30,
#endif
	// OCSP validation of the server certificate implies privacy issues:
	//   - The OCSP request tells the CA which web service the client tries to reach.
	//   - The OCSP requests are sent via unencrypted HTTP, so every "listener in the middle" can see which web service
	//     the client tries to connect.
	// Additionally, the OCSP requests slow down operation and may cause unexpected network traffic, which may trigger
	// security alarms unnecessarily.
	// Due to these issues we explicitly disable OCSP by default.
	//
	// The upside of enabling OCSP mostly is a "real-time" recognition of certificate revocations.
	.ocsp = 0,
	.ocsp_date = 1,
	.ocsp_stapling = 1,
	.ocsp_nonce = 1,
	.netrc = 1,
	.waitretry = 10 * 1000,
#ifdef WITH_GPGME
	.verify_sig = GPG_VERIFY_DISABLED,
	.verify_save_failed = 0,
#endif
	.metalink = 1,
	.tls_false_start = 1,
	.proxy = 1,
#ifdef _WIN32
	.restrict_file_names = WGET_RESTRICT_NAMES_WINDOWS,
#endif
	.local_db = 1,
	.report_speed = WGET_REPORT_SPEED_BYTES,
	.default_http_port = 80,
	.default_https_port = 443,
	.hyperlink = false,
	.if_modified_since = 1,
	.progress = PROGRESS_TYPE_BAR,
	.follow_sitemaps = true
};

static int parse_execute(option_t opt, const char *val, const char invert);
static int parse_proxy(option_t opt, const char *val, const char invert);
static int print_help(WGET_GCC_UNUSED option_t opt, WGET_GCC_UNUSED const char *val, const char invert);


static const struct optionw options[] = {
	// long name, config variable, parse function, number of arguments, short name
	// leave the entries in alphabetical order of 'long_name' !
	{ "accept", &config.accept_patterns, parse_stringlist, 1, 'A',
		SECTION_DOWNLOAD,
		{ "Comma-separated list of file name suffixes or\n",
		  "patterns.\n"
		}
	},
	{ "accept-regex", &config.accept_regex, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Regex matching accepted URLs.\n"
		}
	},
	{ "adjust-extension", &config.adjust_extension, parse_bool, -1, 'E',
		SECTION_HTTP,
		{ "Append extension to saved file (.html or .css).\n",
		  "(default: off)\n"
		}
	},
	{ "append-output", &config.logfile_append, parse_string, 1, 'a',
		SECTION_STARTUP,
		{ "File where messages are appended to, '-' for STDOUT\n"
		}
	},
	{ "ask-password", &config.askpass, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Print prompt for password\n"
		}
	},
	{ "auth-no-challenge", &config.auth_no_challenge, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "send Basic HTTP Authentication before challenge\n" }
	},
	{ "background", &config.background, parse_bool, -1, 'b',
		SECTION_STARTUP,
		{ "Go to background immediately after startup. If no\n",
		  "output file is specified via the -o, output is redirected to wget-log\n"
		}
	},
	{ "backup-converted", &config.backup_converted, parse_bool, -1, 'K',
		SECTION_HTTP,
		{ "When converting, keep the original file with\n",
		  "a .orig suffix. (default: off)\n"
		}
	},
	{ "backups", &config.backups, parse_integer, 1, 0,
		SECTION_DOWNLOAD,
		{ "Make backups instead of overwriting/increasing\n",
		  "number. (default: 0)\n"
		}
	},
	{ "base", &config.base_url, parse_string, 1, 'B',
		SECTION_STARTUP,
		{ "Base for relative URLs read from input-file\n",
		  "or from command line\n"
		}
	},
	{ "bind-address", &config.bind_address, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Bind to sockets to local address.\n",
		  "(default: automatic)\n"
		}
	},
	{ "bind-interface", &config.bind_interface, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Bind sockets to the input Network Interface.\n",
		  "(default: automatic)\n"
		}
	},
	{ "body-data", &config.body_data, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Data to be sent in a request.\n"
		}
	},
	{ "body-file", &config.body_file, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "File with data to be sent in a request.\n"
		}
	},
	{ "ca-certificate", &config.ca_cert, parse_string, 1, 0,
		SECTION_SSL,
		{ "File with bundle of PEM CA certificates.\n"
		}
	},
	{ "ca-directory", &config.ca_directory, parse_string, 1, 0,
		SECTION_SSL,
		{ "Directory with PEM CA certificates.\n"
		}
	},
	{ "cache", &config.cache, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Enabled using of server cache. (default: on)\n"
		}
	},
	{ "certificate", &config.cert_file, parse_string, 1, 0,
		SECTION_SSL,
		{ "File with client certificate.\n"
		}
	},
	{ "certificate-type", &config.cert_type, parse_cert_type, 1, 0,
		SECTION_SSL,
		{ "Certificate type: PEM or DER (known as ASN1).\n",
		  "(default: PEM)\n"
		}
	},
	{ "check-certificate", &config.check_certificate, parse_check_certificate, -1, 0,
		SECTION_SSL,
		{ "Check the server's certificate. (default: on)\n"
		}
	},
	{ "check-hostname", &config.check_hostname, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Check the server's certificate's hostname.\n",
		  "(default: on)\n"
		}
	},
	{ "chunk-size", &config.chunk_size, parse_numbytes, 1, 0,
		SECTION_DOWNLOAD,
		{ "Download large files in multithreaded chunks.\n",
		  "(default: 0 (=off)) Example:\n",
		  "wget --chunk-size=1M\n"
		}
	},
	{ "clobber", &config.clobber, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Enable file clobbering. (default: on)\n"
		}
	},
	{ "compression", &config.compression, parse_compression, -1, 0,
		SECTION_HTTP,
		{ "Customize Accept-Encoding with\n",
		  "identity, gzip, deflate, xz, lzma, br, bzip2, zstd, lzip\n",
		  "and any combination of it\n",
		  "no-compression means no Accept-Encoding\n"
		}
	},
	{ "config", &config.user_config, parse_filename, 1, 0,
		SECTION_STARTUP,
		{ "Path to initialization file (default: ~/.config/wget/wget2rc)\n"
		}
	}, // for backward compatibility only
	{ "connect-timeout", &config.connect_timeout, parse_timeout, 1, 0,
		SECTION_DOWNLOAD,
		{ "Connect timeout in seconds.\n"
		}
	},
	{ "content-disposition", &config.content_disposition, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "Take filename from Content-Disposition.\n",
		  "(default: off)\n"
		}
	},
	{ "content-on-error", &config.content_on_error, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Save response body even on error status.\n",
		  "(default: off)\n"
		}
	},
	{ "continue", &config.continue_download, parse_bool, -1, 'c',
		SECTION_DOWNLOAD,
		{ "Continue download for given files. (default: off)\n"
		}
	},
	{ "convert-file-only", &config.convert_file_only, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Convert only filename part of embedded URLs.\n",
		  "(default: off)\n",
		}
	},
	{ "convert-links", &config.convert_links, parse_bool, -1, 'k',
		SECTION_DOWNLOAD,
		{ "Convert embedded URLs to local URLs.\n",
		  "(default: off)\n"
		}
	},
	{ "cookie-suffixes", &config.cookie_suffixes, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Load public suffixes from file. \n",
		  "They prevent 'supercookie' vulnerabilities.\n",
		  "See https://publicsuffix.org/ for details.\n",
		}
	},
	{ "cookies", &config.cookies, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "Enable use of cookies. (default: on)\n"
		}
	},
	{ "crl-file", &config.crl_file, parse_filename, 1, 0,
		SECTION_SSL,
		{ "File with PEM CRL certificates.\n"
		}
	},
	{ "cut-dirs", &config.cut_directories, parse_integer, 1, 0,
		SECTION_DIRECTORY,
		{ "Skip creating given number of directory\n",
		  "components. (default: 0)\n"
		}
	},
	{ "cut-file-get-vars", &config.cut_file_get_vars, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Cut HTTP GET vars from file names. (default: off)\n"
		}
	},
	{ "cut-url-get-vars", &config.cut_url_get_vars, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Cut HTTP GET vars from URLs. (default: off)\n"
		}
	},
	{ "dane", &config.dane, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Enable DANE certificate checking.(default: off)\n"
		}
	},
	{ "debug", &config.debug, parse_bool, -1, 'd',
		SECTION_STARTUP,
		{ "Print debugging messages.(default: off)\n"
		}
	},
	{ "default-http-port", &config.default_http_port, parse_uint16, 1, 0,
		SECTION_HTTP,
		{ "Set default port for HTTP. (default: 80)\n"
		}
	},
	{ "default-https-port", &config.default_https_port, parse_uint16, 1, 0,
		SECTION_HTTP,
		{ "Set default port for HTTPS. (default: 443)\n"
		}
	},
	{ "default-page", &config.default_page, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Default file name. (default: index.html)\n"
		}
	},
	{ "delete-after", &config.delete_after, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Don't save downloaded files. (default: off)\n"
		}
	},
	{ "directories", &config.directories, parse_bool, -1, 0,
		SECTION_DIRECTORY,
		{ "Create hierarchy of directories when retrieving\n",
		  "recursively. (default: on)\n"
		}
	},
	{ "directory-prefix", &config.directory_prefix, parse_string, 1, 'P',
		SECTION_DIRECTORY,
		{ "Set directory prefix.\n"
		}
	},
	{ "dns-cache", &config.dns_caching, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Caching of domain name lookups. (default: on)\n"
		}
	},
	{ "dns-cache-preload", &config.dns_cache_preload, parse_filename, 1, 0,
		SECTION_DOWNLOAD,
		{ "File to be used to preload the DNS cache.\n",
		  "Format is like /etc/hosts (IP<whitespace>hostname).\n"
		}
	},
	{ "dns-timeout", &config.dns_timeout, parse_timeout, 1, 0,
		SECTION_DOWNLOAD,
		{ "DNS lookup timeout in seconds.\n"
		}
	},
	{ "domains", &config.domains, parse_stringlist, 1, 'D',
		SECTION_DOWNLOAD,
		{ "Comma-separated list of domains to follow.\n"
		}
	},
	{ "download-attr", &config.download_attr, parse_download_attr, -1, 0,
		SECTION_DOWNLOAD,
		{ "Recognize HTML5 download attributes.\n",
		  "'strippath' strips the path to be more secure.\n"
		  "'usepath' uses the path as is (this can be extremely dangerous !).\n"
		  "(default: strippath)\n"
		}
	},
	{ "egd-file", &config.egd_file, parse_filename, 1, 0,
		SECTION_SSL,
		{ "File to be used as socket for random data from\n",
		  "Entropy Gathering Daemon.\n"
		}
	},
	{ "exclude-directories", &config.exclude_directories, parse_excluded_directories, 1, 'X',
		SECTION_DOWNLOAD,
		{ "Comma-separated list of directories NOT to download.\n",
		  "Wildcards are allowed.\n"
		}
	},
	{ "exclude-domains", &config.exclude_domains, parse_stringlist, 1, 0,
		SECTION_DOWNLOAD,
		{ "Comma-separated list of domains NOT to follow.\n"
		}
	},
	{ "execute", NULL, parse_execute, 1, 'e',
		SECTION_STARTUP,
		{ "Wget compatibility option, not needed for Wget\n"
		}
	},
	{ "filter-mime-type", &config.mime_types, parse_stringlist, 1, 0,
		SECTION_DOWNLOAD,
		{ "Specify a list of mime types to be saved or ignored\n"
		}
	},
	{ "filter-urls", &config.filter_urls, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Apply the accept and reject filters on the URL\n",
		  "before starting a download. (default: off)\n"
		}
	},
	{ "follow-sitemaps", &config.follow_sitemaps, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Scan sitemaps found in robots.txt. (default: on)\n"
		}
	},
	{ "follow-tags", &config.follow_tags, parse_taglist, 1, 0,
		SECTION_DOWNLOAD,
		{ "Scan additional tag/attributes for URLs,\n",
		  "e.g. --follow-tags=\"img/data-500px,img/data-hires\n"
		}
	},
	{ "force-atom", &config.force_atom, parse_bool, -1, 0,
		SECTION_STARTUP,
		{ "Treat input file as Atom Feed. (default: off) (NEW!)\n"
		}
	},
	{ "force-css", &config.force_css, parse_bool, -1, 0,
		SECTION_STARTUP,
		{ "Treat input file as CSS. (default: off) (NEW!)\n"
		}
	},
	{ "force-directories", &config.force_directories, parse_bool, -1, 'x',
		SECTION_DIRECTORY,
		{ "Create hierarchy of directories when not\n",
		  "retrieving recursively. (default: off)\n"
		}
	},
	{ "force-html", &config.force_html, parse_bool, -1, 'F',
		SECTION_STARTUP,
		{ "Treat input file as HTML. (default: off)\n"
		}
	},
	{ "force-metalink", &config.force_metalink, parse_bool, -1, 0,
		SECTION_STARTUP,
		{ "Treat input file as Metalink. (default: off) (NEW!)\n"
		}
	},
	{ "force-progress", &config.force_progress, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Force progress bar.\n",
		  "(default: off)\n"
		}
	},
	{ "force-rss", &config.force_rss, parse_bool, -1, 0,
		SECTION_STARTUP,
		{ "Treat input file as RSS Feed. (default: off) (NEW!)\n"
		}
	},
	{ "force-sitemap", &config.force_sitemap, parse_bool, -1, 0,
		SECTION_STARTUP,
		{ "Treat input file as Sitemap. (default: off) (NEW!)\n"
		}
	},
	{ "fsync-policy", &config.fsync_policy, parse_bool, -1, 0,
		SECTION_STARTUP,
		{ "Use fsync() to wait for data being written to\n",
		  "the physical layer. (default: off) (NEW!)\n"
		}
	},
#ifdef WITH_GPGME
	{ "gnupg-homedir", &config.gnupg_homedir, parse_filename, -1, 0,
		SECTION_GPG,
		{ "Specify a directory to use as the GnuPG home\n",
		  " directory. (default: gnupg default homedir)\n"
		}
	},
#endif
	{ "header", &config.headers, parse_header, 1, 0,
		SECTION_HTTP,
		{ "Insert input string as a HTTP header in\n",
		  "all requests\n"
		}
	},
	{ "help", NULL, print_help, 0, 'h',
		SECTION_STARTUP,
		{ "Print this help.\n"
		}
	},
	{ "host-directories", &config.host_directories, parse_bool, -1, 0,
		SECTION_DIRECTORY,
		{ "Create host directories when retrieving\n",
		  "recursively. (default: on)\n"
		}
	},
	{ "hpkp", &config.hpkp, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Use HTTP Public Key Pinning (HPKP). (default: on)\n"
		}
	},
	{ "hpkp-file", &config.hpkp_file, parse_filename, 1, 0,
		SECTION_SSL,
		{ "Set file for storing HPKP data\n",
		  "(default: $XDG_DATA_HOME/wget/.wget-hpkp)\n"
		}
	},
	{ "hsts", &config.hsts, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Use HTTP Strict Transport Security (HSTS).\n",
		  "(default: on)\n"
		}
	},
	{ "hsts-file", &config.hsts_file, parse_filename, 1, 0,
		SECTION_SSL,
		{ "Set file for HSTS caching. (default: $XDG_DATA_HOME/wget/.wget-hsts)\n"
		}
	},
	{ "hsts-preload", &config.hsts_preload, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Use HTTP Strict Transport Security (HSTS).\n",
#ifdef WITH_LIBHSTS
		  "(default: on)\n"
#else
		  "[Not built with libhsts, so not functional]\n"
#endif
		}
	},
	{ "hsts-preload-file", &config.hsts_preload_file, parse_filename, 1, 0,
		SECTION_SSL,
		{ "Set name for the HSTS Preload file (DAFSA format).\n",
#ifdef WITH_LIBHSTS
		  "(default: the distribution's HSTS data file)\n"
#else
		  "[Not built with libhsts, so not functional]\n"
#endif
		}
	},
	{ "html-extension", &config.adjust_extension, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "Obsoleted by --adjust-extension\n"
		}
	}, // obsolete, replaced by --adjust-extension
	{ "http-keep-alive", &config.keep_alive, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "Keep connection open for further requests.\n",
		  "(default: on)\n"
		}
	},
	{ "http-password", &config.http_password, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Password for HTTP Authentication.\n",
		  "(default: empty password)\n"
		}
	},
	{ "http-proxy", &config.http_proxy, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Set HTTP proxy/proxies, overriding environment\n",
		  "variables. Use comma to separate proxies.\n"
		}
	},
	{ "http-proxy-password", &config.http_proxy_password, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Password for HTTP Proxy Authentication.\n",
		  "(default: empty password)\n"
		}
	},
	{ "http-proxy-user", &config.http_proxy_username, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Username for HTTP Proxy Authentication.\n",
		  "(default: empty username)\n"
		}
	},
	{ "http-user", &config.http_username, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Username for HTTP Authentication.\n",
		  "(default: empty username)\n"
		}
	},
	{ "http2", &config.http2, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Use HTTP/2 protocol if possible. (default: on)\n"
		}
	},
	{ "http2-only", &config.http2_only, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Only use HTTP/2 protocol, error if server doesn't offer it. (default: off)\n"
		}
	},
	{ "http2-request-window", &config.http2_request_window, parse_integer, 1, 0,
		SECTION_DOWNLOAD,
		{ "Max. number of parallel streams per HTTP/2\n",
                  "connection. (default: 30)\n"
		}
	},
	{ "https-enforce", &config.https_enforce, parse_https_enforce, 1, 0,
		SECTION_SSL,
		{ "Use secure HTTPS instead of HTTP. Legal types are\n",
                  "'hard', 'soft' and 'none'.\n",
                  "If --https-only is enabled,\n",
                  "this option has no effect. (default: none)\n"
		}
	},
	{ "https-only", &config.https_only, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Do not follow non-secure URLs. (default: off).\n"
		}
	},
	{ "https-proxy", &config.https_proxy, parse_string, 1, 0,
		SECTION_SSL,
		{ "Set HTTPS proxy/proxies, overriding environment\n",
		  "variables. Use comma to separate proxies.\n"
		}
	},
	{ "hyperlink", &config.hyperlink, parse_bool, -1, 0,
		SECTION_STARTUP,
		{ "Enable terminal hyperlink support\n"
		}
	},
	{ "if-modified-since", &config.if_modified_since, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Do not send If-Modified-Since header in -N mode.\n"
		  "Send preliminary HEAD request instead. This has only\n",
		  "effect in -N mode.\n"
		}
	},
	{ "ignore-case", &config.ignore_case, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Ignore case when matching files. (default: off)\n"
		}
	},
	{ "ignore-length", &config.ignore_length, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Ignore content-length header field\n",
		  "(default: off)\n",
		}
	},
	{ "ignore-tags", &config.ignore_tags, parse_taglist, 1, 0,
		SECTION_DOWNLOAD,
		{ "Ignore tag/attributes for URL scanning,\n",
		  "e.g. --ignore-tags=\"img,a/href\n"
		}
	},
	{ "include-directories", &config.exclude_directories, parse_included_directories, 1, 'I',
		SECTION_DOWNLOAD,
		{ "Comma-separated list of directories TO download.\n",
		  "Wildcards are allowed.\n"
		}
	},
	{ "inet4-only", &config.inet4_only, parse_bool, -1, '4',
		SECTION_DOWNLOAD,
		{ "Use IPv4 connections only. (default: off)\n"
		}
	},
	{ "inet6-only", &config.inet6_only, parse_bool, -1, '6',
		SECTION_DOWNLOAD,
		{ "Use IPv6 connections only. (default: off)\n"
		}
	},
	{ "input-encoding", &config.input_encoding, parse_string, 1, 0,
		SECTION_STARTUP,
		{ "Character encoding of the file contents read with\n",
		  "--input-file. (default: local encoding)\n"
		}
	},
	{ "input-file", &config.input_file, parse_string, 1, 'i',
		SECTION_STARTUP,
		{ "File where URLs are read from, - for STDIN.\n"
		}
	},
	{ "iri", NULL, parse_bool, -1, 0, // Wget compatibility, in fact a do-nothing option
		SECTION_DOWNLOAD,
		{ "Wget dummy option, you can't switch off\n",
		  "international support\n"
		}
	},
	{ "keep-extension", &config.keep_extension, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "If file exists: Use pattern 'basename_N.ext'\n",
		  "instead of 'filename.N'. (default: off)\n"
		}
	},
	{ "keep-session-cookies", &config.keep_session_cookies, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "Also save session cookies. (default: off)\n"
		}
	},
	{ "level", &config.level, parse_integer, 1, 'l',
		SECTION_DOWNLOAD,
		{ "Maximum recursion depth. (default: 5)\n"
		}
	},
	{ "limit-rate", &config.limit_rate, parse_numbytes, 1, 0,
		SECTION_HTTP,
		{ "Limit rate of download per second, 0 = no limit. (default: 0)\n"
		}
	},
	{ "list-plugins", NULL, list_plugins, 0, 0,
		SECTION_PLUGIN,
		{ "Lists all the plugins in the plugin search paths.\n"
		}
	},
	{ "load-cookies", &config.load_cookies, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Load cookies from file.\n"
		}
	},
	{ "local-db", &config.local_db, parse_local_db, -1, 0,
		SECTION_STARTUP,
		{ "Read or load databases\n"
		}
	},
	{ "local-encoding", &config.local_encoding, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Character encoding of environment and filenames.\n"
		}
	},
	{ "local-plugin", NULL, parse_plugin_local, 1, 0,
		SECTION_PLUGIN,
		{ "Loads a plugin with a given path.\n"
		}
	},
	{ "max-redirect", &config.max_redirect, parse_integer, 1, 0,
		SECTION_DOWNLOAD,
		{ "Max. number of redirections to follow.\n",
		  "(default: 20)\n"
		}
	},
	{ "max-threads", &config.max_threads, parse_integer, 1, 0,
		SECTION_DOWNLOAD,
		{ "Max. concurrent download threads.\n",
		  "(default: 5) (NEW!)\n"
		}
	},
	{ "metalink", &config.metalink, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "Follow a metalink file instead of storing it\n",
		  "(default: on)\n"
		}
	},
	{ "method", &config.method, parse_string, 1, 0,
		SECTION_HTTP,
		{ "HTTP method to use for request.\n"
		}
	},
	{ "mirror", &config.mirror, parse_mirror, -1, 'm',
		SECTION_DOWNLOAD,
		{ "Turn on mirroring options -r -N -l inf\n"
		}
	},
	{ "n", NULL, parse_n_option, 1, 'n',
		SECTION_STARTUP,
		{ "Special compatibility option\n"
		}
	}, // special Wget compatibility option
	{ "netrc", &config.netrc, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Load credentials from ~/.netrc if not given.\n",
	      "(default: on)\n"
	    }
	},
	{ "netrc-file", &config.netrc_file, parse_filename, 1, 0,
		SECTION_HTTP,
		{ "Set file for login/password to use instead of\n",
		  "~/.netrc. (default: ~/.netrc)\n"
		}
	},
	{ "ocsp", &config.ocsp, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Use OCSP server access to verify server's\n",
		  "certificate. (default: on)\n"
		}
	},
	{ "ocsp-date", &config.ocsp_date, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Check if OCSP response date is too old.\n",
		  "(default: on)\n"
		}
	},
	{ "ocsp-file", &config.ocsp_file, parse_filename, 1, 0,
		SECTION_SSL,
		{ "Set file for OCSP chaching.\n",
		  "(default: $XDG_DATA_HOME/wget/.wget-ocsp)\n"
		}
	},
	{ "ocsp-nonce", &config.ocsp_nonce, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Allow nonce checking when verifying OCSP\n",
		  "response. (default: on)\n"
		}
	},
	{ "ocsp-server", &config.ocsp_server, parse_string, 1, 0,
		SECTION_SSL,
		{ "Set OCSP server address.\n",
		  "(default: OCSP server given in certificate)\n"
		}
	},
	{ "ocsp-stapling", &config.ocsp_stapling, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Use OCSP stapling to verify the server's\n",
		  "certificate. (default: on)\n"
		}
	},
	{ "output-document", &config.output_document, parse_string, 1, 'O',
		SECTION_DOWNLOAD,
		{ "File where downloaded content is written to,\n",
		  "'-O'  for STDOUT.\n"
		}
	},
	{ "output-file", &config.logfile, parse_string, 1, 'o',
		SECTION_STARTUP,
		{ "File where messages are printed to,\n",
		  "'-' for STDOUT.\n"
		}
	},
	{ "page-requisites", &config.page_requisites, parse_bool, -1, 'p',
		SECTION_DOWNLOAD,
		{ "Download all necessary files to display a\n",
		  "HTML page\n"
		}
	},
	{ "parent", &config.parent, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Ascend above parent directory. (default: on)\n"
		}
	},
	{ "password", &config.password, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Password for Authentication.\n",
		  "(default: empty password)\n"
		}
	},
	{ "plugin", NULL, parse_plugin, 1, 0,
		SECTION_PLUGIN,
		{ "Load a plugin with a given name.\n"
		}
	},
	{ "plugin-dirs", NULL, parse_plugin_dirs, 1, 0,
		SECTION_PLUGIN,
		{ "Specify alternative directories to look\n",
		  "for plugins, separated by ','\n"
		}
	},
	{ "plugin-help", NULL, print_plugin_help, 0, 0,
		SECTION_PLUGIN,
		{ "Print help message for all loaded plugins\n"
		}
	},
	{ "plugin-opt", NULL, parse_plugin_option, 1, 0,
		SECTION_PLUGIN,
		{ "Forward an option to a loaded plugin.\n",
		  "The option should be in format:\n",
		  "<plugin_name>.<option>[=value]\n"
		}
	},
	{ "post-data", &config.post_data, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Data to be sent in a POST request.\n"
		}
	},
	{ "post-file", &config.post_file, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "File with data to be sent in a POST request.\n"
		}
	},
	{ "prefer-family", &config.preferred_family, parse_prefer_family, 1, 0,
		SECTION_DOWNLOAD,
		{ "Prefer IPv4 or IPv6. (default: none)\n"
		}
	},
	{ "private-key", &config.private_key, parse_string, 1, 0,
		SECTION_SSL,
		{ "File with private key.\n"
		}
	},
	{ "private-key-type", &config.private_key_type, parse_cert_type, 1, 0,
		SECTION_SSL,
		{ "Type of the private key (PEM or DER).\n",
		  "(default: PEM)\n"
		}
	},
	{ "progress", &config.progress, parse_progress_type, 1, 0,
		SECTION_DOWNLOAD,
		{ "Type of progress bar (bar, none).\n",
		  "(default: none)\n"
		}
	},
	{ "protocol-directories", &config.protocol_directories, parse_bool, -1, 0,
		SECTION_DIRECTORY,
		{ "Force creating protocol directories.\n",
		  "(default: off)\n"
		}
	},
	{ "proxy", &config.proxy, parse_proxy, -1, 0,
		SECTION_DOWNLOAD,
		{ "Enable support for *_proxy environment variables.\n",
		  "(default: on)\n"
		}
	},
	{ "quiet", &config.quiet, parse_bool, -1, 'q',
		SECTION_STARTUP,
		{ "Print no messages except debugging messages.\n",
		  "(default: off)\n"
		}
	},
	{ "quota", &config.quota, parse_numbytes, 1, 'Q',
		SECTION_HTTP,
		{ "Download quota, 0 = no quota. (default: 0)\n"
		}
	},
	{ "random-file", &config.random_file, parse_filename, 1, 0,
		SECTION_SSL,
		{ "File to be used as source of random data.\n"
		}
	},
	{ "random-wait", &config.random_wait, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Wait 0.5 up to 1.5*<--wait> seconds between\n",
		  "downloads (per thread). (default: off)\n"
		}
	},
	{ "read-timeout", &config.read_timeout, parse_timeout, 1, 0,
		SECTION_DOWNLOAD,
		{ "Read and write timeout in seconds.\n"
		}
	},
	{ "recursive", &config.recursive, parse_bool, -1, 'r',
		SECTION_DOWNLOAD,
		{ "Recursive download. (default: off)\n"
		}
	},
	{ "referer", &config.referer, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Include Referer: url in HTTP request.\n",
		  "(default: off)\n"
		}
	},
	{ "regex-type", &config.regex_type, parse_regex_type, 1, 0,
		SECTION_DOWNLOAD,
#if defined WITH_LIBPCRE2 || defined WITH_LIBPCRE
		{ "Regular expression type. Possible types are\n",
                  "posix or pcre. (default: posix)\n" }
#else
		{ "Regular expression type. This build only supports\n",
                  "posix. (default: posix)\n" }
#endif
	},
	{ "reject", &config.reject_patterns, parse_stringlist, 1, 'R',
		SECTION_DOWNLOAD,
		{ "Comma-separated list of file name suffixes or\n",
		  "patterns.\n"
		}
	},
	{ "reject-regex", &config.reject_regex, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Regex matching rejected URLs.\n"
		}
	},
	{ "remote-encoding", &config.remote_encoding, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Character encoding of remote files\n",
		  "(if not specified in Content-Type HTTP header\n",
		  "or in document itself)\n"
		}
	},
	{ "report-speed", &config.report_speed, parse_report_speed_type, 1, 0,
		SECTION_DOWNLOAD,
		{ "Output bandwidth as TYPE. TYPE can be bytes\n",
		  "or bits. --progress MUST be used.\n"
		}
	},
	{ "restrict-file-names", &config.restrict_file_names, parse_restrict_names, 1, 0,
		SECTION_DOWNLOAD,
		{ "unix, windows, nocontrol, ascii, lowercase,\n",
		  "uppercase, none\n"
		}
	},
	{ "retry-connrefused", &config.retry_connrefused, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "Consider \"connection refused\" a transient error.\n",
		  " (default: off)\n"
		}
	},
	{ "retry-on-http-error", &config.retry_on_http_error, parse_stringlist, 1, 0,
		SECTION_DOWNLOAD,
		{ "Specify a list of http statuses in which the download will be retried\n"
		}
	},
	{ "robots", &config.robots, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Respect robots.txt standard for recursive\n",
		  "downloads. (default: on)\n"
		}
	},
	{ "save-content-on", &config.save_content_on, parse_stringlist, 1, 0,
		SECTION_DOWNLOAD,
		{ "Specify a list of response codes that requires it's\n",
		  "response body to be saved on error status\n"
		}
	},
	{ "save-cookies", &config.save_cookies, parse_string, 1, 0,
		SECTION_HTTP,
		{ "Save cookies to file.\n"
		}
	},
	{ "save-headers", &config.save_headers, parse_bool, -1, 0,
		SECTION_HTTP,
		{ "Save the response headers in front of the response\n",
		  "data. (default: off)\n"
		}
	},
	{ "secure-protocol", &config.secure_protocol, parse_string, 1, 0,
		SECTION_SSL,
		{ "Set protocol to be used (auto, SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLS1_3, PFS).\n",
		  "(default: auto). Or use GnuTLS priority\n",
		  "strings, e.g. NORMAL:-VERS-SSL3.0:-RSA\n"
		}
	},
	{ "server-response", &config.server_response, parse_bool, -1, 'S',
		SECTION_DOWNLOAD,
		{ "Print the server response headers. (default: off)\n"
		}
	},
#ifdef WITH_GPGME
	{ "signature-extensions", &config.sig_ext, parse_stringlist, 1, 0,
		SECTION_GPG,
		{ "The extension of the signature file which should be\n",
		  "downloaded. (default: sig)\n"
		}
	},
#endif
	{ "span-hosts", &config.span_hosts, parse_bool, -1, 'H',
		SECTION_DOWNLOAD,
		{ "Span hosts that were not given on the\n",
		  "command line. (default: off)\n"
		}
	},
	{ "spider", &config.spider, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Enable web spider mode. (default: off)\n"
		}
	},
	{ "start-pos", &config.start_pos, parse_numbytes, 1, 0,
		SECTION_DOWNLOAD,
		{ "Start downloading at zero-based position, 0 = option disabled. (default: 0)\n"
		}
	},
	{ "stats-dns", &config.stats_dns_args, parse_stats, 1, 0,
		SECTION_STARTUP,
		{ "Print DNS stats. (default: off)\n",
		  "Additional format supported:\n",
		  "--stats-dns=[FORMAT:]FILE\n"
		}
	},
	{ "stats-ocsp", &config.stats_ocsp_args, parse_stats, 1, 0,
		SECTION_STARTUP,
		{ "Print OCSP stats. (default: off)\n",
		  "Additional format supported:\n",
		  "--stats-ocsp=[FORMAT:]FILE\n"
		}
	},
	{ "stats-server", &config.stats_server_args, parse_stats, 1, 0,
		SECTION_STARTUP,
		{ "Print server stats. (default: off)\n",
		  "Additional format supported:\n",
		  "--stats-server=[FORMAT:]FILE\n"
		}
	},
	{ "stats-site", &config.stats_site_args, parse_stats, 1, 0,
		SECTION_STARTUP,
		{ "Print site stats. (default: off)\n",
		  "Additional format supported:\n",
		  "--stats-site=[FORMAT:]FILE\n"
		}
	},
	{ "stats-tls", &config.stats_tls_args, parse_stats, 1, 0,
		SECTION_STARTUP,
		{ "Print TLS stats. (default: off)\n",
		  "Additional format supported:\n",
		  "--stats-tls=[FORMAT:]FILE\n"
		}
	},
	{ "strict-comments", &config.strict_comments, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "A dummy option. Parsing always works non-strict.\n"
		}
	},
	{ "tcp-fastopen", &config.tcp_fastopen, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Enable TCP Fast Open (TFO). (default: on)\n"
		}
	},
	{ "timeout", NULL, parse_timeout, 1, 'T',
		SECTION_DOWNLOAD,
		{ "General network timeout in seconds.\n"
		}
	},
	{ "timestamping", &config.timestamping, parse_bool, -1, 'N',
		SECTION_DOWNLOAD,
		{ "Just retrieve younger files than the local ones.\n",
		  "(default: off)\n"
		}
	},
	{ "tls-false-start", &config.tls_false_start, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Enable TLS False Start (needs GnuTLS 3.5+).\n",
		  "(default: on)\n"
		}
	},
	{ "tls-resume", &config.tls_resume, parse_bool, -1, 0,
		SECTION_SSL,
		{ "Enable TLS Session Resumption. (default: off)\n"
		}
	},
	{ "tls-session-file", &config.tls_session_file, parse_filename, 1, 0,
		SECTION_SSL,
		{ "Set file for TLS Session caching.\n",
		  "(default: $XDG_DATA_HOME/wget/.wget-session)\n"
		}
	},
	{ "tries", &config.tries, parse_integer, 1, 't',
		SECTION_DOWNLOAD,
		{ "Number of tries for each download. (default 20)\n"
		}
	},
	{ "trust-server-names", &config.trust_server_names, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "On redirection use the server's filename.\n",
		  "(default: off)\n"
		}
	},
	{ "unlink", &config.unlink, parse_bool, -1, 0,
		SECTION_STARTUP,
		{ "Remove files before clobbering. (default: off)\n"
		}
	},
	{ "use-askpass", &config.use_askpass_bin, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Prompt for a user and password using\n",
                  "the specified command.\n"
		}
	},
	{ "use-server-timestamps", &config.use_server_timestamps, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Set local file's timestamp to server's timestamp.\n",
		  "(default: on)\n"
		}
	},
	{ "user", &config.username, parse_string, 1, 0,
		SECTION_DOWNLOAD,
		{ "Username for Authentication.\n",
		  "(default: empty username)\n"
		}
	},
	{ "user-agent", &config.user_agent, parse_string, 1, 'U',
		SECTION_HTTP,
		{ "HTTP User Agent string.\n",
		  "(default: wget)\n"
		}
	},
	{ "verbose", &config.verbose, parse_bool, -1, 'v',
		SECTION_STARTUP,
		{ "Print more messages. (default: on)\n"
		}
	},
#ifdef WITH_GPGME
	{ "verify-save-failed", &config.verify_save_failed, parse_bool, -1, 0,
		SECTION_GPG,
		{ "Save target files even when their signatures fail\n",
		  "GPG validation. (default: off)\n"
		}
	},
	{ "verify-sig", &config.verify_sig, parse_verify_sig, -1, 's',
		SECTION_GPG,
		{ "Download .sig file and verify. (default: off)\n"
		}
	},
#endif
	{ "version", NULL, print_version, 0, 'V',
		SECTION_STARTUP,
		{ "Display the version of Wget and exit.\n"
		}
	},
	{ "wait", &config.wait, parse_timeout, 1, 'w',
		SECTION_DOWNLOAD,
		{ "Wait number of seconds between downloads\n",
		  "(per thread). (default: 0)\n"
		}
	},
	{ "waitretry", &config.waitretry, parse_timeout, 1, 0,
		SECTION_DOWNLOAD,
		{ "Wait up to number of seconds after error\n",
		  "(per thread). (default: 10)\n"
		}
	},
	{ "xattr", &config.xattr, parse_bool, -1, 0,
		SECTION_DOWNLOAD,
		{ "Save extended file attributes. (default: off)\n"\
		}
	}
};

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static int print_help(WGET_GCC_UNUSED option_t opt, WGET_GCC_UNUSED const char *val, WGET_GCC_UNUSED const char invert)
{
	set_exit_status(EXIT_STATUS_NO_ERROR);
	return -1; // stop processing & exit
}
#else
static inline void print_first(const char s, const char *l, const char *msg)
{
	if (strlen(l) > 18) {
		printf("  %c%-2c --%s\n",
			(s ? '-' : ' '),
			(s ? s : ' '),
			l);
		printf("%28s%s", "", msg);
	} else
		printf("  %c%-2c --%-18.18s  %s",
			(s ? '-' : ' '),
			(s ? s : ' '),
			l, msg);
}

static inline void print_next(const char *msg)
{
	printf("%30s%s", "", msg);
}

static int print_help(WGET_GCC_UNUSED option_t opt, WGET_GCC_UNUSED const char *val, WGET_GCC_UNUSED const char invert)
{
	printf(
		"GNU Wget2 V" PACKAGE_VERSION " - multithreaded metalink/file/website downloader\n"
		"\n"
		"Usage: wget [options...] <url>...\n"
		"\n");

	for (help_section_t sect = SECTION_STARTUP; sect < SECTION_END; sect++) {
		switch (sect) {
		case SECTION_STARTUP:
			printf("Startup:\n");
			break;

		case SECTION_DOWNLOAD:
			printf("Download:\n");
			break;

		case SECTION_HTTP:
			printf("HTTP related options:\n");
			break;

		case SECTION_SSL:
			printf("HTTPS (SSL/TLS) related options:\n");
			break;

		case SECTION_DIRECTORY:
			printf("Directory options:\n");
			break;

#ifdef WITH_GPGME
		case SECTION_GPG:
			printf("GPG related options:\n");
			break;
#endif

		case SECTION_PLUGIN:
			printf("Plugin options:\n");
			break;

		case SECTION_END:
			// fallthrough
		default:
			printf("Unknown help section %d\n", (int) sect);
			exit(EXIT_FAILURE);
		}
		for (unsigned it = 0; it < countof(options); it++) {
			if (options[it].section == sect) {
				if (options[it].short_name == 'n')
					continue; // do not display this special compatibility catch -n* option
				print_first(options[it].short_name,
				            options[it].long_name,
				            options[it].help_str[0]);
				for (unsigned i = 1; i < countof(options[it].help_str) && options[it].help_str[i] != NULL; i++)
					print_next(options[it].help_str[i]);
			}
		}
		printf("\n");
	}

	printf("\n");
	printf("Example boolean option:\n --quiet=no is the same as --no-quiet or --quiet=off or --quiet off\n");
	printf("Example string option:\n --user-agent=SpecialAgent/1.3.5 or --user-agent \"SpecialAgent/1.3.5\"\n");
	printf("\n");
	printf("To reset string options use --[no-]option\n");
	printf("\n");

/*
 * -a / --append-output should be reduced to -o (with always appending to logfile)
 * Using rm logfile + wget achieves the old behaviour...
 *
 */
	set_exit_status(EXIT_STATUS_NO_ERROR);
	return -1; // stop processing & exit
}
#endif

static int WGET_GCC_PURE WGET_GCC_NONNULL_ALL opt_compare(const void *key, const void *option)
{
	return strcmp(key, ((option_t) option)->long_name);
}

static int WGET_GCC_PURE WGET_GCC_NONNULL_ALL opt_compare_config(const void *key, const void *option)
{
	return wget_strcasecmp_ascii(key, ((option_t) option)->long_name);
}

static int WGET_GCC_PURE WGET_GCC_NONNULL_ALL opt_compare_config_linear(const char *key, const char *command)
{
	const char *s1 = key, *s2 = command;

	for (; *s1 && *s2; s1++, s2++) {
		if (*s2 == '-' || *s2 == '_') {
			if (*s1 == '-' || *s1 == '_')
				s1++;
			s2++;
		}

		if (!*s1 || !*s2 || c_tolower(*s1) != *s2) break;
		// *s2 is guaranteed to be lower case so convert *s1 to lower case
	}

	return *s1 != *s2; // no need for tolower() here
}

// return values:
//  < 0 : parse error
// >= 0 : number of arguments processed
static int WGET_GCC_NONNULL((1)) set_long_option(const char *name, const char *value, char parsing_config)
{
	option_t opt;
	char invert = 0, value_present = 0, case_insensitive = 1;
	char namebuf[sizeof(options[0].long_name) + 5], *p;
	int ret = 0, rc;

	if ((p = strchr(name, '='))) {
		// option with appended value
		if (p - name >= (int) sizeof(namebuf)) {
			error_printf(_("Unknown option '%s'\n"), name);
			return -1;
		}
		memcpy(namebuf, name, p - name);
		namebuf[p - name] = 0;
		name = namebuf;
		value = p + 1;
		value_present = 1;
	}

	// If the option is  passed from .wget2rc (--*), delete the "--" prefix
	if (!strncmp(name, "--", 2)) {
		case_insensitive = 0;
		name += 2;
	}
	// If the option is negated (--no-) delete the "no-" prefix
	if (!strncmp(name, "no-", 3)) {
		invert = 1;
		name += 3;
	}

	if (parsing_config && case_insensitive) {
		opt = bsearch(name, options, countof(options), sizeof(options[0]), opt_compare_config);
		if (!opt) {
			// Fallback to linear search for 'unsharp' searching.
			// Maybe the user asked for e.g. https_only or httpsonly instead of https-only
			// opt_compare_config_linear() will find these. Wget -e/--execute compatibility.
			for (unsigned it = 0; it < countof(options) && !opt; it++)
				if (opt_compare_config_linear(name, options[it].long_name) == 0)
					opt = &options[it];
		}
	} else
		opt = bsearch(name, options, countof(options), sizeof(options[0]), opt_compare);

	if (!opt) {
		error_printf(_("Unknown option '%s'\n"), name);
		return -1;
	}

	if (value_present) {
		// "option=*"
		if (invert) {
			if (!opt->args ||
				opt->parser == parse_string ||
				opt->parser == parse_stringset ||
				opt->parser == parse_stringlist ||
				opt->parser == parse_filename ||
				opt->parser == parse_filenames ||
				opt->parser == parse_stats)
			{
				error_printf(_("Option 'no-%s' doesn't allow an argument\n"), name);
				return -1;
			}
		} else if (!opt->args) {
			error_printf(_("Option '%s' doesn't allow an argument\n"), name);
			return -1;
		}
	} else {
		// "option"
		switch (opt->args) {
		case 0:
			value = NULL;
			break;
		case 1:
			if (!value) {
				error_printf(_("Missing argument for option '%s'\n"), name);
				// empty string is allowed in value i.e. *value = '\0'
				return -1;
			}

			if (invert && (
				opt->parser == parse_string ||
				opt->parser == parse_stringset ||
				opt->parser == parse_stringlist ||
				opt->parser == parse_filename ||
				opt->parser == parse_filenames ||
				opt->parser == parse_stats))
			{
				value = NULL;
			} else
				ret = opt->args;
			break;
		case -1:
			if (!parsing_config)
				value = NULL;
			else if (value)
				ret = 1;
			break;
		default:
			break;
		}
	}

	if ((rc = opt->parser(opt, value, invert)) < 0)
		return rc;

	return ret;
}

static int parse_proxy(option_t opt, const char *val, const char invert)
{
	if (parse_bool(opt, val, invert) < 0) {
		if (invert) {
			// the strdup'ed string will be released on program exit
			xfree(config.no_proxy);
			config.no_proxy = val ? wget_strdup(val) : NULL;
		} else {
			if((opt = bsearch("http-proxy", options, countof(options), sizeof(options[0]), opt_compare)))
				return parse_string(opt, val, invert);
			if((opt = bsearch("https-proxy", options, countof(options), sizeof(options[0]), opt_compare)))
				return parse_string(opt, val, invert);
		}
	}

	return 0;
}

static int parse_execute(WGET_GCC_UNUSED option_t opt, const char *val, WGET_GCC_UNUSED const char invert)
{
	// info_printf("### argv=%s val=%s\n",argv[0],val);
	return set_long_option(val, NULL, 1);
}

static int parse_option(char *linep, char **name, char **val)
{
	int quote;

	while (c_isspace(*linep)) linep++;
	for (*name = linep; c_isalnum(*linep) || *linep == '-' || *linep == '_'; linep++);

	if (!**name) {
		error_printf(_("Failed to parse: '%s'\n"), linep);
		// continue;
		return 0;
	}

	if (c_isspace(*linep)) {
		*linep++ = 0;
		while (c_isspace(*linep)) linep++;
	}

	if (*linep == '=') {
		// option with value, e.g. debug=y
		*linep++ = 0;
		while (c_isspace(*linep)) linep++;

		*val = linep;

		if (((quote = *linep) == '\"' || quote == '\'')) {
			char *src = linep + 1, *dst = linep, c;

			while ((c = *src) != quote && c) {
				if (c == '\\' && src[1]) {
					// we could extend \r, \n etc to control codes here
					// but it is not needed so far
					*dst++ = src[1];
					src += 2;
				} else *dst++ = *src++;
			}
			*dst = 0;
		}
		return 1;
	} else {
		// statement (e.g. include ".wgetrc.d") or boolean option without value (e.g. no-recursive)
		if (*linep) *linep++ = 0;
		while (c_isspace(*linep)) linep++;
		*val = linep;
		return 2;
	}
}

// read and parse config file (not thread-safe !)
// - first, leading and trailing whitespace are trimmed
// - lines beginning with '#' are comments, except the line before has a trailing slash
// - there are no multiline comments (trailing \ on comments will be ignored)
// - empty lines are ignored
// - lines consisting only of whitespace are ignored
// - a trailing \ will append the next line (this does not go for comments!)
// - if the last line has a trailing \, it will be ignored
// - format is 'name value', where value might be enclosed in ' or "
// - values enclosed in " or ' might contain \\, \" and \'

static int WGET_GCC_NONNULL((1)) read_config_expand(const char *cfgfile, int expand)
{
	static int level; // level of recursions to prevent endless include loops
	FILE *fp;
	char *buf = NULL, *linep, *name, *val;
	int append = 0, found, ret = 0, rc;
	size_t bufsize = 0;
	ssize_t len;
	wget_buffer linebuf;

	if (++level > 20) {
		error_printf(_("Config file recursion detected in %s\n"), cfgfile);
		level--;
		return -2;
	}

	if (expand) {
		glob_t globbuf = { .gl_pathc = 0 };

		if (glob(cfgfile, GLOB_MARK | GLOB_TILDE, NULL, &globbuf) == 0) {
			size_t it;

			for (it = 0; it < globbuf.gl_pathc && ret == 0; it++) {
				if (globbuf.gl_pathv[it][strlen(globbuf.gl_pathv[it])-1] != '/') {
					ret = read_config_expand(globbuf.gl_pathv[it], 0);
				}
			}

			globfree(&globbuf);
		} else {
			ret = read_config_expand(cfgfile, 0);
		}

		level--;
		return ret;
	}

	if ((fp = fopen(cfgfile, "r")) == NULL) {
		error_printf(_("Failed to open %s (%d): %s\n"), cfgfile, errno, strerror(errno));
		level--;
		return -1;
	}

	debug_printf("Reading %s\n", cfgfile);

	char tmp[1024];
	wget_buffer_init(&linebuf, tmp, sizeof(tmp));

	while (ret == 0 && (len = wget_getline(&buf, &bufsize, fp)) >= 0) {
		if (len == 0 || *buf == '\r' || *buf == '\n') continue;

		linep = buf;

		// remove leading whitespace (only on non-continuation lines)
		if (!append)
			while (c_isspace(*linep)) {
				linep++;
				len--;
			}
		if (*linep == '#') continue;

		// remove trailing whitespace
		while (len > 0 && c_isspace(linep[len - 1]))
			len--;
		linep[len] = 0;

		if (len > 0 && linep[len - 1] == '\\') {
			if (append) {
				wget_buffer_memcat(&linebuf, linep, len - 1);
			} else {
				wget_buffer_memcpy(&linebuf, linep, len - 1);
				append = 1;
			}
			continue;
		} else if (append) {
			wget_buffer_strcat(&linebuf, linep);
			append = 0;
			linep = linebuf.data;
		}

		found = parse_option(linep, &name, &val);

		if (found == 1) {
			// debug_printf("%s = %s\n",name,val);
			if ((rc = set_long_option(name, val, 1)) < 0)
				ret = rc;
		} else if (found == 2) {
			// debug_printf("%s %s\n",name,val);
			if (!strcmp(name, "include")) {
				ret = read_config_expand(val, 1);
			} else {
				if ((rc = set_long_option(name, NULL, 0)) < 0)
					ret = rc;
			}
		}
	}

	wget_buffer_deinit(&linebuf);
	xfree(buf);
	fclose(fp);

	if (append) {
		error_printf(_("Failed to parse last line in '%s'\n"), cfgfile);
		ret = -4;
	}

	level--;
	return ret;
}

static bool read_config(void)
{
	bool ret = true;

	if (config.system_config)
		ret = read_config_expand(config.system_config, 1);

	if (config.user_config)
		ret &= read_config_expand(config.user_config, 1);

	return ret;
}

static int WGET_GCC_NONNULL((2)) parse_command_line(int argc, const char **argv)
{
	static short shortcut_to_option[128];
	const char *first_arg = NULL;
	int n, rc;

	// init the short option lookup table
	if (!shortcut_to_option[0]) {
		for (short it = 0; it < (short) countof(options); it++) {
			if (options[it].short_name > 0)
				shortcut_to_option[(unsigned char)options[it].short_name] = it + 1;
		}
	}

	// I like the idea of getopt() but not it's implementation (e.g. global variables).
	// Therefore I implement my own getopt() behavior.
	for (n = 1; n < argc && first_arg != argv[n]; n++) {
		const char *argp = argv[n];

		if (argp[0] != '-') {
			// Move args behind options to allow mixed args/options like getopt().
			// In the end, the order of the args is as before.
			const char *cur = argv[n];
			for (int it = n; it < argc - 1; it++)
				argv[it] = argv[it + 1];
			argv[argc - 1] = cur;

			// Once we see the first arg again, we are done
			if (!first_arg)
				first_arg = cur;

			n--;
			continue;
		}

		if (argp[1] == '-') {
			// long option
			if (argp[2] == 0)
				return n + 1;

			if ((rc = set_long_option(argp + 2, n < argc - 1 ? argv[n+1] : NULL, 0)) < 0)
				return rc;

			n += rc;

		} else if (argp[1]) {
			// short option(s)
			for (int pos = 1; argp[pos]; pos++) {
				option_t opt;
				int idx;

				if (c_isalnum(argp[pos]) && (idx = shortcut_to_option[(unsigned char)argp[pos]])) {
					opt = &options[idx - 1];
					// info_printf("opt=%p [%c]\n",(void *)opt,argp[pos]);
					// info_printf("name=%s\n",opt->long_name);
					if (opt->args > 0) {
						const char *val;

						if (!argp[pos + 1] && argc <= n + opt->args) {
							error_printf(_("Missing argument(s) for option '-%c'\n"), argp[pos]);
							return -1;
						}
						val = argp[pos + 1] ? argp + pos + 1 : argv[++n];
						if ((rc = opt->parser(opt, val, 0)) < 0)
							return rc;
						n += rc;
						break;
					} else {//if (opt->args == 0)
						if ((rc = opt->parser(opt, NULL, 0)) < 0)
							return rc;
					}
/*					else {
						const char *val;
						val = argp[pos + 1] ? argp + pos + 1 : NULL;
						n += opt->parser(opt, val);
						break;
					}
*/
				} else {
					error_printf(_("Unknown option '-%c'\n"), argp[pos]);
					return -1;
				}
			}
		}
	}

	return n;
}

// Return the user's home directory (strdup-ed), or NULL if none is found.
static const char *get_home_dir(bool free_home)
{
	static const char *home;

	if (free_home) {
		xfree(home);
		return NULL;
	}

	if (!home) {
		if ((home = wget_strnglob("~", 1, GLOB_TILDE_CHECK)) == NULL)
			home = wget_strdup("."); // Use the current directory as 'home' directory
	}

	return home;
}

static char *prompt_for_password(void)
{
	if (config.username)
		wget_fprintf (stderr, _("Password for user \"%s\": "), config.username);
	else
		wget_fprintf (stderr, _("Password: "));

	if (!is_testing())
		return getpass("");
	else
		return wget_strdup("xxx");
}

/* Execute external application config.use_askpass_bin */
static int run_use_askpass(const char *question, char **answer)
{
	char tmp[1024];
	pid_t pid;
	int rc, ret = -1;
	int com[2];
	bool fa_valid = false;
	ssize_t bytes = 0;
	char const * const argv[] = { config.use_askpass_bin, question, NULL };
	posix_spawn_file_actions_t fa;

	if (pipe(com) == -1) {
		error_printf(_("Cannot create pipe"));
		return -1;
	}

	rc = posix_spawn_file_actions_init(&fa);
	if (rc) {
		error_printf(_("Error initializing spawn file actions for use-askpass: %d"), rc);
		goto cleanup;
	}
	fa_valid = 1;

	rc = posix_spawn_file_actions_addclose(&fa, com[0]);
	if (!rc)
		rc = posix_spawn_file_actions_adddup2(&fa, com[1], STDOUT_FILENO);
	if (!rc)
		rc = posix_spawn_file_actions_addclose(&fa, com[1]);
	if (rc) {
		error_printf(_("Error setting spawn file actions for use-askpass: %d"), rc);
		goto cleanup;
	}

	if (!is_testing()) {
		rc = posix_spawnp(&pid, config.use_askpass_bin, &fa, NULL, (char * const *) argv, environ);
		if (rc) {
			error_printf(_("Error spawning %s: %d"), config.use_askpass_bin, rc);
			goto cleanup;
		}
	}

	/* Parent process reads from child. */
	close(com[1]); com[1] = -1;

	if (!is_testing()) {
		bytes = read(com[0], tmp, sizeof(tmp) - 1);
	} else {
		// fuzzing: random number of read bytes
		bytes = rand() % (sizeof(tmp) - 1);
		memset(tmp, 'x', bytes);
	}

	if (bytes <= 0) {
		error_printf(_("Error reading response from command \"%s %s\": %s\n"),
			config.use_askpass_bin, question, strerror (errno));
		goto cleanup;
	}

	/* Set the end byte to \0, and decrement bytes */
	tmp[bytes--] = '\0';

	/* Remove a possible new line */
	while (bytes >= 0 && (tmp[bytes] == '\n' || tmp[bytes] == '\r'))
		tmp[bytes--] = '\0';

	*answer = wget_strdup(tmp);

	ret = 0;

cleanup:
	if (com[1] != -1)
		close(com[1]);
	if (com[0] != -1)
		close(com[0]);
	if (fa_valid)
		posix_spawn_file_actions_destroy(&fa);

	return ret;
}

static int use_askpass(void)
{
	char question[1024];

	xfree(config.username);

	/* Prompt for username */
	if (run_use_askpass("Type username:", &config.username) < 0)
		return -1;

	wget_snprintf(question, sizeof(question), "Type password for '%s':", config.username);
	xfree(config.password);

	/* Prompt for password */
	if (run_use_askpass(question, &config.password) < 0)
		return -1;

	return 0;
}

/*
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
*/

static wget_dns_cache *dns_cache;
static wget_dns *dns;

static int preload_dns_cache(const char *fname)
{
	FILE *fp;
	char buf[256], ip[64], name[256];

	// wget_options_fuzzer sets config.dont_write, avoid waiting for stdin input forever
	if (!strcmp(fname, "-") && !config.dont_write)
		fp = stdin;
	else if (!(fp = fopen(fname, "r"))) {
		error_printf(_("Failed to open %s"), fname);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "%63s %255s", ip, name) != 2)
			continue;

		wget_strtolower(name);

		debug_printf("Adding DNS Mapping: %s -> %s\n", name, ip);
		wget_dns_cache_ip(dns, ip, name, 80);
		wget_dns_cache_ip(dns, ip, name, 443);
	}

	if (fp != stdin)
		fclose(fp);

	return 0;
}

static void WGET_GCC_NONNULL_ALL get_config_files(const char *config_home, const char *user_home)
{
	const char *env;

	// First add the Global Wget2rc file.
	if ((env = getenv ("SYSTEM_WGET2RC")) && *env) {
		config.system_config = wget_strdup(env);
	} else if (config.system_config) {
		if (access(config.system_config, R_OK) != 0)
			xfree(config.system_config);
	}

	if ((env = getenv("WGET2RC")) && *env) {
		// If the WGET2RC variable is set, then load that file
		config.user_config = wget_strdup(env);
	} else {
		const char *path = wget_aprintf("%s/wget2rc", config_home);
		if (access(path, R_OK) == 0)
			config.user_config = path;
		else
			xfree(path);
	}

	// XXX: This is a compatibility shim and should be removed by the next
	// release.
	if (!config.user_config) {
		const char *path = wget_aprintf("%s/.wget2rc", user_home);
		if (access(path, R_OK) == 0) {
			config.user_config = path;
			error_printf(_("~/.wget2rc is deprecated. Please move it to %s/wget2rc\n"), config_home);
		} else {
			xfree(path);
		}
	}
}

static const char *get_xdg_data_home(const char *user_home)
{
	static const char *data_home = NULL;
	const char *env;

	if (!user_home) {
		xfree(data_home);
		return NULL;
	}

	if (data_home)
		return data_home;

#ifdef _WIN32
	if ((env = getenv("LOCALAPPDATA")) && *env)
		data_home = wget_aprintf("%s/wget", env);
	else
		data_home = wget_strdup(user_home);
#else
	if ((env = getenv("XDG_DATA_HOME")) && *env)
		data_home = wget_aprintf("%s/wget", env);
	else {
		data_home = wget_aprintf("%s/.local/share/wget", user_home);
	}
#endif
	mkdir_path(data_home, false);
	return data_home;
}

static const char *get_xdg_config_home(const char *user_home)
{
	// According to the XDG Basedir Spec, configuration data goes into
	// $XDG_CONFIG_HOME, or ~/.config. On Windows, the closest alternative is
	// %LOCALAPPDATA%. We would like to store the Wget2 configuration files
	// within a separate wget directory.
	static const char *home_dir = NULL;
	const char *env;

	if (!user_home) {
		xfree(home_dir);
		return NULL;
	}

	if (home_dir)
		return home_dir;

#ifdef _WIN32
	if ((env = getenv("LOCALAPPDATA")) && *env)
		home_dir = wget_aprintf("%s/wget", env);
	else
		home_dir = wget_strdup(user_home);
#else
	if ((env = getenv("XDG_CONFIG_HOME")) && *env)
		home_dir = wget_aprintf("%s/wget", env);
	else
		home_dir = wget_aprintf("%s/.config/wget", user_home);
#endif

	return home_dir;
}

static void stats_callback_dns(wget_dns *_dns, wget_dns_stats_data *stats, void *ctx)
{
	(void) _dns;
	FILE *fp = (FILE *) ctx;

	if (config.stats_dns_args->format == WGET_STATS_FORMAT_HUMAN) {
		if (wget_ip_is_family(stats->hostname, WGET_NET_FAMILY_IPV6)) {
			wget_fprintf(fp, "  %4lld [%s]:%hu (%s)\n",
				stats->dns_secs,
				stats->hostname ? stats->hostname : "-",
				stats->port,
				stats->ip ? stats->ip : "-");
		} else {
			wget_fprintf(fp, "  %4lld %s:%hu (%s)\n",
				stats->dns_secs,
				stats->hostname ? stats->hostname : "-",
				stats->port,
				stats->ip ? stats->ip : "-");
		}
	} else {
		wget_fprintf(fp, "%s,%s,%hu,%lld\n",
			stats->hostname,
			stats->ip,
			stats->port,
			stats->dns_secs);
	}
}

static void stats_callback_ocsp(wget_ocsp_stats_data *stats, void *ctx)
{
	FILE *fp = (FILE *) ctx;

	if (config.stats_ocsp_args->format == WGET_STATS_FORMAT_HUMAN) {
		wget_fprintf(fp, "  %s:\n", stats->hostname);
		wget_fprintf(fp, "    Stapling       : %d\n", stats->stapling);
		wget_fprintf(fp, "    Valid          : %d\n", stats->nvalid);
		wget_fprintf(fp, "    Revoked        : %d\n", stats->nrevoked);
		wget_fprintf(fp, "    Ignored        : %d\n\n", stats->nignored);
	} else {
		wget_fprintf(fp, "%s,%d,%d,%d,%d\n",
			stats->hostname,
			stats->stapling,
			stats->nvalid,
			stats->nrevoked,
			stats->nignored);
	}
}

static const char *tlsversion_string(int v)
{
	switch (v) {
	case 1: return "SSL3";
	case 2: return "TLS1.0";
	case 3: return "TLS1.1";
	case 4: return "TLS1.2";
	case 5: return "TLS1.3";
	default: return "?";
	}
}

static void stats_callback_tls(wget_tls_stats_data *stats, void *ctx)
{
	FILE *fp = (FILE *) ctx;

	if (config.stats_tls_args->format == WGET_STATS_FORMAT_HUMAN) {
		wget_fprintf(fp, "  %s:\n", stats->hostname);
		wget_fprintf(fp, "    Version         : %s\n", tlsversion_string(stats->version));
		wget_fprintf(fp, "    False Start     : %s\n", ON_OFF_DASH(stats->false_start));
		wget_fprintf(fp, "    TFO             : %s\n", ON_OFF_DASH(stats->tfo));
		wget_fprintf(fp, "    ALPN Protocol   : %s\n", stats->alpn_protocol ? stats->alpn_protocol : "-");
		wget_fprintf(fp, "    Resumed         : %s\n", YES_NO(stats->resumed));
		wget_fprintf(fp, "    TCP Protocol    : %s\n", HTTP_1_2(stats->http_protocol));
		wget_fprintf(fp, "    Cert Chain Size : %d\n", stats->cert_chain_size);
		wget_fprintf(fp, "    TLS negotiation\n");
		wget_fprintf(fp, "    duration (ms)   : %lld\n\n", stats->tls_secs);
	} else {
		wget_fprintf(fp, "%s,%d,%d,%d,%d,%s,%d,%d,%lld\n",
			stats->hostname,
			stats->version,
			stats->false_start,
			stats->tfo,
			stats->resumed,
			stats->alpn_protocol ? stats->alpn_protocol : "",
			stats->http_protocol,
			stats->cert_chain_size,
			stats->tls_secs);
	}
}

// read config, parse CLI options, check values, set module options
// and return the number of arguments consumed
int init(int argc, const char **argv)
{
	int n, rc;

	// use our own allocation functions so we can print error + exit() in a out-of-memory situation
	set_allocation_functions();

	// this is a special case for switching on debugging before any config file is read
	if (argc >= 2) {
		if (!strcmp(argv[1],"-d"))
			config.debug = 1;
		else if (!strcmp(argv[1],"--debug")) {
			if ((rc = set_long_option(argv[1] + 2, argv[2], 0)) < 0)
				return rc;
		}
	}

	// Initialize some configuration values which depend on the Runtime environment
	const char *home_dir = get_home_dir(false);
	const char *xdg_config_home = get_xdg_config_home(home_dir);
	const char *xdg_data_home = get_xdg_data_home(home_dir);

	// We need these because the parse_string() method will attempt to free the
	// value before setting a new one. Hence, these must be dynamically
	// allocated
	config.user_agent = wget_strdup(config.user_agent);
	config.secure_protocol = wget_strdup(config.secure_protocol);
	config.ca_directory = wget_strdup(config.ca_directory);
	config.ca_cert = wget_strdup(config.ca_cert);
	config.default_page = wget_strdup(config.default_page);
	config.system_config = wget_strdup(config.system_config);

	log_init();

	get_config_files(xdg_config_home, home_dir);

	// first processing, to respect options that might influence output
	// while read_config() (e.g. -d, -q, -a, -o)
	if (parse_command_line(argc, argv) < 0)
		return -1;

	// truncate logfile, if not in append mode
	if (config.logfile_append) {
		xfree(config.logfile);
		config.logfile = config.logfile_append;
		config.logfile_append = NULL;
	}
	else if (config.logfile && strcmp(config.logfile, "-") && !config.dont_write) {
		int fd = open(config.logfile, O_WRONLY | O_TRUNC);

		if (fd != -1)
			close(fd);
	}
	log_init();

	if (config.hsts && !config.hsts_file)
		config.hsts_file = wget_aprintf("%s/.wget-hsts", xdg_data_home);

	if (config.hpkp && !config.hpkp_file)
		config.hpkp_file = wget_aprintf("%s/.wget-hpkp", xdg_data_home);

	if (config.tls_resume && !config.tls_session_file)
		config.tls_session_file = wget_aprintf("%s/.wget-session", xdg_data_home);

	if (config.ocsp && !config.ocsp_file)
		config.ocsp_file = wget_aprintf("%s/.wget-ocsp", xdg_data_home);

	if (config.netrc && !config.netrc_file)
		config.netrc_file = wget_aprintf("%s/.netrc", home_dir);

#ifdef WITH_LIBHSTS
	if (config.hsts_preload && !config.hsts_preload_file && *hsts_dist_filename())
		config.hsts_preload_file = wget_strdup(hsts_dist_filename());
#endif

	wget_vector_free(&config.exclude_directories); // -I and -X stack up, so free before final command line parsing

	//Enable plugin loading
	{
		const char *path;

		plugin_loading_enabled = 1;
		path = getenv("WGET2_PLUGIN_DIRS");
		if (path) {
			plugin_db_clear_search_paths();
#ifdef _WIN32
			plugin_db_add_search_paths(path, ';');
#else
			plugin_db_add_search_paths(path, ':');
#endif
		}

		if (plugin_db_load_from_envvar()) {
			set_exit_status(EXIT_STATUS_PARSE_INIT);
			return -1; // stop processing & exit
		}
	}

	// read global config and user's config
	// settings in user's config override global settings
	read_config();

	// now read command line options which override the settings of the config files
	if ((n = parse_command_line(argc, argv)) < 0)
		return -1;

	if (plugin_db_help_forwarded()) {
		set_exit_status(EXIT_STATUS_NO_ERROR);
		return -1; // stop processing & exit
	}

	if (config.logfile_append) {
		xfree(config.logfile);
		config.logfile = config.logfile_append;
		config.logfile_append = NULL;
	}
	else if (config.logfile && strcmp(config.logfile, "-") && !config.dont_write) {
		// truncate logfile
		int fd = open(config.logfile, O_WRONLY | O_TRUNC);

		if (fd != -1)
			close(fd);
	}

	log_init();

	if (config.logfile) {
		// Currently, we do not support mixing progress bar and log output.
		config.progress = PROGRESS_TYPE_NONE;
	}

	if (config.https_only && config.https_enforce)
		// disable https enforce if https-only is enabled
		config.https_enforce = HTTPS_ENFORCE_NONE;

	wget_iri_set_defaultport(WGET_IRI_SCHEME_HTTP, config.default_http_port);
	wget_iri_set_defaultport(WGET_IRI_SCHEME_HTTPS, config.default_https_port);

	// check for correct settings
	if (config.max_threads < 1 || (config.max_threads > 1 && config.chunk_size))
		config.max_threads = 1;

	if (config.hyperlink) {
		config.hostname = xgethostname();
	}

	// truncate output document but not if -c is used
	if (config.output_document && strcmp(config.output_document, "-") && !config.dont_write) {
		if (config.unlink) {
			unlink(config.output_document);
		} else if (!config.continue_download) {
			int fd = open(config.output_document, O_WRONLY | O_TRUNC | O_BINARY);

			if (fd != -1)
				close(fd);
		}
	}

	if (!config.local_encoding)
		config.local_encoding = wget_local_charset_encoding();
	if (!config.input_encoding)
		config.input_encoding = wget_strdup(config.local_encoding);

	debug_printf("Local URI encoding = '%s'\n", config.local_encoding);
	debug_printf("Input URI encoding = '%s'\n", config.input_encoding);

//Set environ proxy var only if a corresponding command-line proxy var isn't supplied
	if (config.proxy) {
		if (!config.http_proxy)
			config.http_proxy = wget_strdup(getenv("http_proxy"));
		if (!config.https_proxy)
			config.https_proxy = wget_strdup(getenv("https_proxy"));
		if (!config.no_proxy)
			config.no_proxy = wget_strdup(getenv("no_proxy"));
	}

	if (config.http_proxy && *config.http_proxy && !wget_http_set_http_proxy(config.http_proxy, config.local_encoding)) {
		error_printf(_("Failed to set http proxies %s\n"), config.http_proxy);
		return -1;
	}
	if (config.https_proxy && *config.https_proxy && !wget_http_set_https_proxy(config.https_proxy, config.local_encoding)) {
		error_printf(_("Failed to set https proxies %s\n"), config.https_proxy);
		return -1;
	}
	if (config.no_proxy && wget_http_set_no_proxy(config.no_proxy, config.local_encoding) < 0) {
		error_printf(_("Failed to set proxy exceptions %s\n"), config.no_proxy);
		return -1;
	}
	xfree(config.http_proxy);
	xfree(config.https_proxy);
	xfree(config.no_proxy);

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	if (config.cookies) {
		config.cookie_db = wget_cookie_db_init(NULL);
		wget_cookie_set_keep_session_cookies(config.cookie_db, config.keep_session_cookies);
		if (config.cookie_suffixes)
			wget_cookie_db_load_psl(config.cookie_db, config.cookie_suffixes);
		if (config.load_cookies)
			wget_cookie_db_load(config.cookie_db, config.load_cookies);
	}

	if (config.hsts) {
		if (!config.hsts_db)
			config.hsts_db = wget_hsts_db_init(NULL, config.hsts_file);
		wget_hsts_db_load(config.hsts_db);
	}

#ifdef WITH_LIBHSTS
	if (config.hsts_preload && config.hsts_preload_file) {
		if ((rc = hsts_load_file(config.hsts_preload_file, &config.hsts_preload_data))) {
			wget_error_printf(_("Failed to load %s (%d)"), config.hsts_preload_file, rc);
		}
	}
#endif

	if (config.hpkp) {
		if (!config.hpkp_db)
			config.hpkp_db = wget_hpkp_db_init(NULL, config.hpkp_file);
		wget_hpkp_db_load(config.hpkp_db);
	}

	if (config.tls_resume) {
		config.tls_session_db = wget_tls_session_db_init(NULL);
		wget_tls_session_db_load(config.tls_session_db, config.tls_session_file);
	}

	if (config.ocsp) {
		if (!config.ocsp_db)
			config.ocsp_db = wget_ocsp_db_init(NULL, config.ocsp_file);
		wget_ocsp_db_load(config.ocsp_db);
	}
#endif

	if (config.base_url)
		config.base = wget_iri_parse(config.base_url, config.local_encoding);

	if (config.askpass && n < argc) {
		xfree(config.password);
		config.password = prompt_for_password();
	}

	if (config.use_askpass_bin && n < argc && use_askpass() < 0)
		return -1;

	if (!config.http_username)
		config.http_username = wget_strdup(config.username);

	if (!config.http_password)
		config.http_password = wget_strdup(config.password);

	if (!config.http_proxy_username)
		config.http_proxy_username = wget_strdup(config.username);

	if (!config.http_proxy_password)
		config.http_proxy_password = wget_strdup(config.password);

	if (config.auth_no_challenge) {
		config.default_challenges = wget_vector_create(1, NULL);
		wget_http_challenge *basic = wget_calloc(1, sizeof(wget_http_challenge));
		basic->auth_scheme = wget_strdup("basic");
		wget_vector_add(config.default_challenges, basic);
		wget_vector_set_destructor(config.default_challenges, (wget_vector_destructor *) wget_http_free_challenge);
	}

	if (config.page_requisites && !config.recursive) {
		config.recursive = 1;
		config.level = 1;
	}

	if (config.start_pos && config.continue_download) {
		error_printf(_("Specifying both --start-pos and --continue is not recommended; --continue will be disabled"));
		config.continue_download = 0;
	}

	if (config.timestamping) {
		if (config.output_document) {
			error_printf(_("WARNING: timestamping does nothing in combination with -O"));
			config.timestamping = 0;
		}
		if (!config.clobber) {
			error_printf(_("Can't timestamp and not clobber old files at the same time"));
			config.timestamping = 0;
		}
		if (config.spider) {
			error_printf(_("WARNING: timestamping does nothing in combination with spider"));
			config.timestamping = 0;
		}
		if (config.chunk_size && config.if_modified_since) {
			error_printf(_("WARNING: timestamping and chunk-size only work together without If-Modified-Since"));
			config.if_modified_since = 0;
		}
	}

	if (config.mirror)
		config.metalink = 0;

	if (config.verify_sig) {
#ifdef WITH_GPGME
		init_gpgme();
		if (!config.sig_ext) {
			config.sig_ext = wget_vector_create(1, (wget_vector_compare_fn *) strcmp);
			wget_vector_add(config.sig_ext, wget_strdup("sig"));
		} else {

			// Dedupe ...
			// Duplicate extensions break the chain when "add_url" blocks the requests
			// so they don't come back as a failure.
			int start_len = wget_vector_size(config.sig_ext);
			wget_vector *new_sig_ext = wget_vector_create(start_len, (wget_vector_compare_fn *) strcmp);
			wget_stringmap *set = wget_stringmap_create(start_len);
			for (int i = 0; i < start_len; i++) {
				const char *nxt = wget_vector_get(config.sig_ext, i);
				if (!wget_stringmap_contains(set, nxt)) {
					wget_vector_add(new_sig_ext, wget_strdup(nxt));
					wget_stringmap_put(set, wget_strdup(nxt), NULL);
				}
			}

			wget_vector_free(&config.sig_ext);
			wget_stringmap_free(&set);
			config.sig_ext = new_sig_ext;
			new_sig_ext = NULL;
		}
#endif
	}

	if ((rc = wget_net_init())) {
		wget_error_printf(_("Failed to init networking (%d)"), rc);
		return -1;
	}

	if ((rc = wget_dns_init(&dns))) {
		wget_error_printf(_("Failed to init DNS (%d)"), rc);
		return -1;
	}
	if (config.dns_caching) {
		if ((rc = wget_dns_cache_init(&dns_cache))) {
			wget_error_printf(_("Failed to init DNS cache (%d)"), rc);
			return -1;
		}
		wget_dns_set_cache(dns, dns_cache);
	}
	wget_dns_set_timeout(dns, config.dns_timeout);
	wget_tcp_set_dns(NULL, dns);

	if (config.stats_dns_args) {
		config.stats_dns_args->fp =
			config.stats_dns_args->filename && *config.stats_dns_args->filename && strcmp(config.stats_dns_args->filename, "-")
			&& !config.dont_write ? fopen(config.stats_dns_args->filename, "w") : stdout;
		if (!config.stats_dns_args->fp) {
			wget_error_printf(_("Failed to open '%s' (%d)"), config.stats_dns_args->filename, rc);
			return -1;
		}
		wget_dns_set_stats_callback(dns, stats_callback_dns, config.stats_dns_args->fp);
	}

	if (config.stats_ocsp_args) {
		config.stats_ocsp_args->fp =
			config.stats_ocsp_args->filename && *config.stats_ocsp_args->filename && strcmp(config.stats_ocsp_args->filename, "-")
			&& !config.dont_write ? fopen(config.stats_ocsp_args->filename, "w") : stdout;
		if (!config.stats_ocsp_args->fp) {
			wget_error_printf(_("Failed to open '%s' (%d)"), config.stats_ocsp_args->filename, rc);
			return -1;
		}
		wget_ssl_set_stats_callback_ocsp(stats_callback_ocsp, config.stats_ocsp_args->fp);
	}

	if (config.stats_tls_args) {
		config.stats_tls_args->fp =
			config.stats_tls_args->filename && *config.stats_tls_args->filename && strcmp(config.stats_tls_args->filename, "-")
			&& !config.dont_write ? fopen(config.stats_tls_args->filename, "w") : stdout;
		if (!config.stats_tls_args->fp) {
			wget_error_printf(_("Failed to open '%s' (%d)"), config.stats_tls_args->filename, rc);
			return -1;
		}
		wget_ssl_set_stats_callback_tls(stats_callback_tls, config.stats_tls_args->fp);
	}

	if (config.stats_server_args) {
		config.stats_server_args->fp =
			config.stats_server_args->filename && *config.stats_server_args->filename && strcmp(config.stats_server_args->filename, "-")
			&& !config.dont_write ? fopen(config.stats_server_args->filename, "w") : stdout;
		if (!config.stats_server_args->fp) {
			wget_error_printf(_("Failed to open '%s' (%d)"), config.stats_server_args->filename, rc);
			return -1;
		}
		server_stats_init(config.stats_server_args->fp);
	}

	if (config.stats_site_args) {
		config.stats_site_args->fp =
			config.stats_site_args->filename && *config.stats_site_args->filename && strcmp(config.stats_site_args->filename, "-")
			&& !config.dont_write ? fopen(config.stats_site_args->filename, "w") : stdout;
		if (!config.stats_site_args->fp) {
			wget_error_printf(_("Failed to open '%s' (%d)"), config.stats_site_args->filename, rc);
			return -1;
		}
		site_stats_init(config.stats_site_args->fp);
	}

	// set module specific options
	wget_tcp_set_timeout(NULL, config.read_timeout);
	wget_tcp_set_connect_timeout(NULL, config.connect_timeout);
	wget_tcp_set_tcp_fastopen(NULL, config.tcp_fastopen);
	wget_tcp_set_tls_false_start(NULL, config.tls_false_start);
	if (!config.dont_write) // fuzzing mode, try to avoid real network access
		wget_tcp_set_bind_address(NULL, config.bind_address);
	if (config.bind_interface)
		wget_tcp_set_bind_interface(NULL, config.bind_interface);
	if (config.inet4_only)
		wget_tcp_set_family(NULL, WGET_NET_FAMILY_IPV4);
	else if (config.inet6_only)
		wget_tcp_set_family(NULL, WGET_NET_FAMILY_IPV6);
	else
		wget_tcp_set_preferred_family(NULL, config.preferred_family);

	wget_iri_set_defaultpage(config.default_page);

	// SSL settings
	wget_ssl_set_config_int(WGET_SSL_CHECK_CERTIFICATE, config.check_certificate == CHECK_CERTIFICATE_ENABLED);
	wget_ssl_set_config_int(WGET_SSL_REPORT_INVALID_CERT, config.check_certificate != CHECK_CERTIFICATE_LOG_DISABLED);
	wget_ssl_set_config_int(WGET_SSL_CHECK_HOSTNAME, config.check_hostname);
	wget_ssl_set_config_int(WGET_SSL_CERT_TYPE, config.cert_type);
#ifdef WITH_LIBDANE
	wget_ssl_set_config_int(WGET_SSL_DANE, config.dane);
#endif
	wget_ssl_set_config_int(WGET_SSL_KEY_TYPE, config.private_key_type);
	wget_ssl_set_config_int(WGET_SSL_PRINT_INFO, config.debug);
	wget_ssl_set_config_int(WGET_SSL_OCSP, config.ocsp);
#ifndef WITH_LIBWOLFCRYPT
	wget_ssl_set_config_int(WGET_SSL_OCSP_DATE, config.ocsp_date);
	wget_ssl_set_config_int(WGET_SSL_OCSP_NONCE, config.ocsp_nonce);
#endif
	wget_ssl_set_config_int(WGET_SSL_OCSP_STAPLING, config.ocsp_stapling);
	wget_ssl_set_config_string(WGET_SSL_OCSP_SERVER, config.ocsp_server);
	wget_ssl_set_config_string(WGET_SSL_SECURE_PROTOCOL, config.secure_protocol);
	wget_ssl_set_config_string(WGET_SSL_CA_DIRECTORY, config.ca_directory);
	wget_ssl_set_config_string(WGET_SSL_CA_FILE, config.ca_cert);
	wget_ssl_set_config_string(WGET_SSL_CERT_FILE, config.cert_file);
	wget_ssl_set_config_string(WGET_SSL_KEY_FILE, config.private_key);
	wget_ssl_set_config_string(WGET_SSL_CRL_FILE, config.crl_file);
	wget_ssl_set_config_object(WGET_SSL_OCSP_CACHE, config.ocsp_db);
#ifdef WITH_LIBNGHTTP2
	if (config.http2_only)
		wget_ssl_set_config_string(WGET_SSL_ALPN, config.http2 ? "h2" : NULL);
	else
		wget_ssl_set_config_string(WGET_SSL_ALPN, config.http2 ? "h2,http/1.1" : NULL);
#endif
	wget_ssl_set_config_object(WGET_SSL_SESSION_CACHE, config.tls_session_db);
	wget_ssl_set_config_object(WGET_SSL_HPKP_CACHE, config.hpkp_db);

	// convert host lists to lowercase
	for (int it = 0; it < wget_vector_size(config.domains); it++) {
		char *s, *hostname = wget_vector_get(config.domains, it);

		wget_percent_unescape(hostname);

		if (wget_str_needs_encoding(hostname)) {
			if ((s = wget_str_to_utf8(hostname, config.local_encoding))) {
				wget_vector_replace(config.domains, s, it);
				hostname = s;
			}

			if ((s = (char *)wget_str_to_ascii(hostname)) != hostname)
				wget_vector_replace(config.domains, s, it);
		} else
			wget_strtolower(hostname);
	}

	for (int it = 0; it < wget_vector_size(config.exclude_domains); it++) {
		char *s, *hostname = wget_vector_get(config.exclude_domains, it);

		wget_percent_unescape(hostname);

		if (wget_str_needs_encoding(hostname)) {
			if ((s = wget_str_to_utf8(hostname, config.local_encoding))) {
				wget_vector_replace(config.exclude_domains, s, it);
				hostname = s;
			}

			if ((s = (char *)wget_str_to_ascii(hostname)) != hostname)
				wget_vector_replace(config.exclude_domains, s, it);
		} else
			wget_strtolower(hostname);
	}

	if (config.dns_cache_preload)
		preload_dns_cache(config.dns_cache_preload);

	return n;
}

// just needs to be called to free all allocated storage on exit
// for valgrind testing

void deinit(void)
{
	wget_global_deinit();

	// Free the home directories
	get_home_dir(true);
	get_xdg_config_home(NULL);
	get_xdg_data_home(NULL);

	wget_dns_free(&dns);
	wget_dns_cache_free(&dns_cache);

	wget_cookie_db_free(&config.cookie_db);
	wget_hsts_db_free(&config.hsts_db);
	wget_hpkp_db_free(&config.hpkp_db);
	wget_tls_session_db_free(&config.tls_session_db);
	wget_ocsp_db_free(&config.ocsp_db);
	wget_netrc_db_free(&config.netrc_db);

	xfree(config.accept_regex);
	xfree(config.base_url);
	xfree(config.bind_address);
	xfree(config.bind_interface);
	xfree(config.body_data);
	xfree(config.body_file);
	xfree(config.ca_cert);
	xfree(config.ca_directory);
	xfree(config.cert_file);
	xfree(config.cookie_suffixes);
	xfree(config.crl_file);
	xfree(config.default_page);
	xfree(config.directory_prefix);
	xfree(config.egd_file);
	xfree(config.hsts_file);
	xfree(config.hpkp_file);
	xfree(config.http_password);
	xfree(config.http_proxy);
	xfree(config.http_proxy_password);
	xfree(config.http_proxy_username);
	xfree(config.http_username);
	xfree(config.https_proxy);
	xfree(config.hsts_preload_file);
	xfree(config.input_encoding);
	xfree(config.input_file);
	xfree(config.load_cookies);
	xfree(config.local_encoding);
	xfree(config.logfile);
	xfree(config.logfile_append);
	xfree(config.method);
	xfree(config.hostname);
	xfree(config.netrc_file);
	xfree(config.ocsp_file);
	xfree(config.ocsp_server);
	xfree(config.output_document);
	xfree(config.password);
	xfree(config.post_data);
	xfree(config.post_file);
	xfree(config.private_key);
	xfree(config.random_file);
	xfree(config.referer);
	xfree(config.reject_regex);
	xfree(config.remote_encoding);
	xfree(config.save_cookies);
	xfree(config.secure_protocol);
	xfree(config.tls_session_file);
	xfree(config.user_agent);
	xfree(config.use_askpass_bin);
	xfree(config.username);
	xfree(config.gnupg_homedir);
	xfree(config.stats_all);
	xfree(config.user_config);
	xfree(config.system_config);

	if (config.stats_dns_args) {
		if (config.stats_dns_args->fp && config.stats_dns_args->fp != stdout)
			fclose(config.stats_dns_args->fp);
		xfree(config.stats_dns_args->filename);
		xfree(config.stats_dns_args);
	}

	if (config.stats_ocsp_args) {
		if (config.stats_ocsp_args->fp && config.stats_ocsp_args->fp != stdout)
			fclose(config.stats_ocsp_args->fp);
		xfree(config.stats_ocsp_args->filename);
		xfree(config.stats_ocsp_args);
	}

	if (config.stats_server_args) {
		if (config.stats_server_args->fp)
			server_stats_exit();
		if (config.stats_server_args->fp && config.stats_server_args->fp != stdout)
			fclose(config.stats_server_args->fp);
		xfree(config.stats_server_args->filename);
		xfree(config.stats_server_args);
	}

	if (config.stats_site_args) {
		if (config.stats_site_args->fp)
			site_stats_exit();
		if (config.stats_site_args->fp && config.stats_site_args->fp != stdout)
			fclose(config.stats_site_args->fp);
		xfree(config.stats_site_args->filename);
		xfree(config.stats_site_args);
	}

	if (config.stats_tls_args) {
		if (config.stats_tls_args->fp && config.stats_tls_args->fp != stdout)
			fclose(config.stats_tls_args->fp);
		xfree(config.stats_tls_args->filename);
		xfree(config.stats_tls_args);
	}

	wget_iri_free(&config.base);

	wget_vector_free(&config.exclude_directories);
	wget_vector_free(&config.save_content_on);
	wget_vector_free(&config.mime_types);
	wget_vector_free(&config.retry_on_http_error);
	wget_vector_free(&config.domains);
	wget_vector_free(&config.exclude_domains);
	wget_vector_free(&config.follow_tags);
	wget_vector_free(&config.ignore_tags);
	wget_vector_free(&config.accept_patterns);
	wget_vector_free(&config.reject_patterns);
	wget_vector_free(&config.headers);
	wget_vector_free(&config.default_challenges);
	wget_vector_free(&config.compression);
#ifdef WITH_GPGME
	wget_vector_free(&config.sig_ext);
#endif
	wget_http_set_http_proxy(NULL, NULL);
	wget_http_set_https_proxy(NULL, NULL);
	wget_http_set_no_proxy(NULL, NULL);


#ifdef WITH_LIBHSTS
	hsts_free(config.hsts_preload_data);
	config.hsts_preload_data = NULL;
#endif
}

// self test some functions, called by using --self-test

int selftest_options(void)
{
	int ret = 0;
	size_t it;

	// check if all options are in order (using opt_compare)

	for (it = 1; it < countof(options); it++) {
		if (opt_compare(options[it - 1].long_name, &options[it]) > 0) {
			error_printf(_("%s: Option not in order '%s' after '%s' (using opt_compare())\n"), __func__, options[it].long_name, options[it - 1].long_name);
			ret = 1;
		}
	}

	// check if all options are in order (using opt_compare_config)

	for (it = 1; it < countof(options); it++) {
		if (opt_compare_config(options[it - 1].long_name, &options[it]) > 0) {
			error_printf(_("%s: Option not in order '%s' after '%s' (using opt_compare_config())\n"), __func__, options[it].long_name, options[it - 1].long_name);
			ret = 1;
		}
	}

	// check if all options are available (using opt_compare)

	for (it = 0; it < countof(options); it++) {
		option_t opt = bsearch(options[it].long_name, options, countof(options), sizeof(options[0]), opt_compare);
		if (!opt) {
			error_printf(_("%s: Failed to find option '%s' (using opt_compare())\n"), __func__, options[it].long_name);
			ret = 1;
		}
	}

	// check if all options are available (using opt_compare_config)

	for (it = 0; it < countof(options); it++) {
		option_t opt = bsearch(options[it].long_name, options, countof(options), sizeof(options[0]), opt_compare_config);
		if (!opt) {
			error_printf(_("%s: Failed to find option '%s' (using opt_compare_config())\n"), __func__, options[it].long_name);
			ret = 1;
		}
	}

	// explicit test cases for opt_compare_config

	{
		static const char *test_command[] = {
			"httpproxy",
			"http_proxy",
			"http-proxy",
			"Httpproxy",
			"Http_proxy",
			"Http-proxy",
		};

		for (it = 0; it < countof(test_command); it++) {
			option_t opt = bsearch(test_command[it], options, countof(options), sizeof(options[0]), opt_compare_config);
			if (!opt) {
				for (unsigned it2 = 0; it2 < countof(options) && !opt; it2++)
					if (opt_compare_config_linear(test_command[it], options[it2].long_name) == 0)
						opt = &options[it2];
				if (!opt) {
					error_printf(_("%s: Failed to find option '%s' (using opt_compare_config())\n"), __func__, test_command[it]);
					ret = 1;
				}
			}
		}
	}

	// test parsing boolean short and long option

	{
		static struct {
			const char
				*argv[3];
			bool
				result;
		} test_bool_short[] = {
			{ { "", "-r", "-" }, 1 },
		};

		// save config values
		bool recursive = config.recursive;

		for (it = 0; it < countof(test_bool_short); it++) {
			parse_command_line(3, test_bool_short[it].argv);
			if (config.recursive != test_bool_short[it].result) {
				error_printf(_("%s: Failed to parse bool short option #%zu (=%d)\n"), __func__, it, config.recursive);
				ret = 1;
			}
		}

		static struct {
			const char
				*argv[3];
			char
				result;
		} test_bool[] = {
			{ { "", "--recursive", "" }, 1 },
			{ { "", "--no-recursive", "" }, 0 },
			{ { "", "--recursive=y", "" }, 1 },
			{ { "", "--recursive=n", "" }, 0 },
			{ { "", "--recursive=1", "" }, 1 },
			{ { "", "--recursive=0", "" }, 0 },
			{ { "", "--recursive=yes", "" }, 1 },
			{ { "", "--recursive=no", "" }, 0 },
			{ { "", "--recursive=on", "" }, 1 },
			{ { "", "--recursive=off", "" }, 0 }
		};

		for (it = 0; it < countof(test_bool); it++) {
			parse_command_line(2, test_bool[it].argv);
			if (config.recursive != test_bool[it].result) {
				error_printf(_("%s: Failed to parse bool long option #%zu (%d)\n"), __func__, it, config.recursive);
				ret = 1;
			}

			parse_command_line(3, test_bool[it].argv);
			if (config.recursive != test_bool[it].result) {
				error_printf(_("%s: Failed to parse bool long option #%zu (%d)\n"), __func__, it, config.recursive);
				ret = 1;
			}
		}

		// restore config values
		config.recursive = recursive;
	}

	// test parsing timeout short and long option

	{
		static struct {
			const char
				*argv[3];
			int
				result;
		} test_timeout_short[] = {
			{ { "", "-T", "123" }, 123000 },
			{ { "", "-T", "-1" }, -1 },
			{ { "", "-T", "inf" }, -1 },
			{ { "", "-T", "infinity" }, -1 },
			{ { "", "-T", "0" }, -1 }, // -1 due to special wget compatibility
			{ { "", "-T", "+123" }, 123000 },
			{ { "", "-T", "60.2" }, 60200 },
			{ { "", "-T123", "" }, 123000 },
			{ { "", "-T-1", "" }, -1 },
			{ { "", "-Tinf", "" }, -1 },
			{ { "", "-Tinfinity", "" }, -1 },
			{ { "", "-T0", "" }, -1 }, // -1 due to special wget compatibility
			{ { "", "-T+123", "" }, 123000 },
			{ { "", "-T60.2", "" }, 60200 }
		};

		// save config values
		int dns_timeout = config.dns_timeout;
		int connect_timeout = config.connect_timeout;
		int read_timeout = config.read_timeout;

		for (it = 0; it < countof(test_timeout_short); it++) {
			config.dns_timeout = 555; // some value not used in test
			parse_command_line(3, test_timeout_short[it].argv);
			if (config.dns_timeout != test_timeout_short[it].result) {
				error_printf(_("%s: Failed to parse timeout short option #%zu (=%d)\n"), __func__, it, config.dns_timeout);
				ret = 1;
			}
		}

		static struct {
			const char
				*argv[3];
			int
				result;
		} test_timeout[] = {
			{ { "", "--timeout", "123" }, 123000 },
			{ { "", "--timeout", "-1" }, -1 },
			{ { "", "--timeout", "inf" }, -1 },
			{ { "", "--timeout", "infinity" }, -1 },
			{ { "", "--timeout", "0" }, -1 }, // -1 due to special wget compatibility
			{ { "", "--timeout", "+123" }, 123000 },
			{ { "", "--timeout", "60.2" }, 60200 },
			{ { "", "--timeout=123", "" }, 123000 },
			{ { "", "--timeout=-1", "" }, -1 },
			{ { "", "--timeout=inf", "" }, -1 },
			{ { "", "--timeout=infinity", "" }, -1 },
			{ { "", "--timeout=0", "" }, -1 }, // -1 due to special wget compatibility
			{ { "", "--timeout=+123", "" }, 123000 },
			{ { "", "--timeout=60.2", "" }, 60200 }
		};

		for (it = 0; it < countof(test_timeout); it++) {
			config.dns_timeout = 555;  // some value not used in test
			parse_command_line(3, test_timeout[it].argv);
			if (config.dns_timeout != test_timeout[it].result) {
				error_printf(_("%s: Failed to parse timeout long option #%zu (%d)\n"), __func__, it, config.dns_timeout);
				ret = 1;
			}
		}

		// restore config values
		config.dns_timeout = dns_timeout;
		config.connect_timeout = connect_timeout;
		config.read_timeout = read_timeout;
	}

	// Test parsing --header option
	{
		static struct {
			const char
				*argv[5];
			const char
				*result[2];
		} test_header[] = {
			{ { "", "--header", "Hello: World", "", "" }, {"Hello", "World" } },
			{ { "", "--header=Hello: World", "--header", "", "" }, {NULL, NULL} },
			{ { "", "--header=Hello: World", "--header", "", "--header=Test: Passed" }, {"Test", "Passed"} },
		};

		// Empty the header list before proceeding
		wget_vector_clear(config.headers);

		for (it = 0; it < countof(test_header); it++) {
			const char *res_name = test_header[it].result[0];
			const char *res_value = test_header[it].result[1];

			parse_command_line(5, test_header[it].argv);
			wget_http_header_param *config_value = wget_vector_get(config.headers, 0);
			if (res_name == NULL) {
				if (wget_vector_size(config.headers) != 0) {
					error_printf(_("%s: Extra headers found in option #%zu\n"), __func__, it);
					ret = 1;
				}
			} else if (wget_strcmp(config_value->name, res_name) &&
					wget_strcmp(config_value->value, res_value)) {
				error_printf(_("%s: Failed to parse header option #%zu\n"), __func__, it);
				ret = 1;
			}
		}

		// Test illegal values
		static struct {
			const char
				*argv[3];
		} test_header_illegal[] = {
			{ { "", "--header", "Hello World" } },
			{ { "", "--header", "Hello:" } },
			{ { "", "--header", "Hello:  " } },
			{ { "", "--header", ":World" } },
			{ { "", "--header", ":" } },
		};

		// Empty the header list before proceeding
		wget_vector_clear(config.headers);

		for (it = 0; it < countof(test_header_illegal); it++) {
			parse_command_line(3, test_header_illegal[it].argv);
			if (wget_vector_size(config.headers) != 0) {
				error_printf(_("%s: Accepted illegal header option #%zu\n"), __func__, it);
				ret = 1;
			}
		}

		// Empty the header list before proceeding
		wget_vector_clear(config.headers);
	}
	// test parsing string short and long option

	{
		static struct {
			const char
				*argv[3];
			const char
				*result;
		} test_string_short[] = {
			{ { "", "-U", "hello1" }, "hello1" },
			{ { "", "-Uhello2", "" }, "hello2" }
		};

		// save config values
		const char *user_agent = config.user_agent;
		config.user_agent = NULL;

		for (it = 0; it < countof(test_string_short); it++) {
			parse_command_line(3, test_string_short[it].argv);
			if (wget_strcmp(config.user_agent, test_string_short[it].result)) {
				error_printf(_("%s: Failed to parse string short option #%zu (=%s)\n"), __func__, it, config.user_agent);
				ret = 1;
			}
		}

		static struct {
			const char
				*argv[3];
			const char
				*result;
		} test_string[] = {
			{ { "", "--user-agent", "hello3" }, "hello3" },
			{ { "", "--user-agent=hello4", "" }, "hello4" },
			{ { "", "--no-user-agent", "" }, NULL }
		};

		for (it = 0; it < countof(test_string); it++) {
			parse_command_line(3, test_string[it].argv);
			if (wget_strcmp(config.user_agent, test_string[it].result)) {
				error_printf(_("%s: Failed to parse string short option #%zu (=%s)\n"), __func__, it, config.user_agent);
				ret = 1;
			}
		}

		// restore config values
		xfree(config.user_agent);
		config.user_agent = user_agent;
	}

	return ret;
}

WGET_GCC_NORETURN
static void no_memory(void)
{
	fputs("No memory\n", stderr);
	exit(EXIT_FAILURE);
}

WGET_GCC_RETURNS_NONNULL
static void *my_malloc(size_t size)
{
	void *p = malloc(size) ; // space before ; is intentional to trick out syntax-check

	if (p)
		return p;

	no_memory();
}

WGET_GCC_RETURNS_NONNULL
static void *my_calloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size) ; // space before ; is intentional to trick out syntax-check

	if (p)
		return p;

	no_memory();
}

WGET_GCC_RETURNS_NONNULL
static void *my_realloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size) ; // space before ; is intentional to trick out syntax-check

	if (p || (ptr && size == 0))
		return p;

	no_memory();
}

static void my_free(void *ptr)
{
	free(ptr) ; // space before ; is intentional to trick out syntax-check
}

static void set_allocation_functions(void)
{
	wget_malloc_fn = my_malloc;
	wget_calloc_fn = my_calloc;
	wget_realloc_fn = my_realloc;
	wget_free = my_free;
}

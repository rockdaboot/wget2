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
 * test routines
 *
 * Changelog
 * 06.07.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <libmget.h>

#define info_printf printf
#define error_printf printf
#define xfree(a) do { if (a) { free((void *)(a)); a=NULL; } } while (0)
#define countof(a) (sizeof(a)/sizeof(*(a)))

void
	mget_cookie_free_public_suffixes(void);
int
	mget_cookie_load_public_suffixes(const char *fname);
int
	mget_cookie_suffix_match(const char *domain);

typedef struct {
	char
		label_buf[42];
	const char *
		label;
	unsigned short
		length;
	unsigned char
		nlabels, // number of labels
		wildcard; // this is a wildcard rule (e.g. *.sapporo.jp)
} PUBLIC_SUFFIX;

static mget_vector_t
	*_suffixes,
	*_suffix_exceptions;

// by this kind of sorting, we can easily see if a domain matches or not (match = supercookie !)

static int G_GNUC_MGET_NONNULL_ALL _suffix_compare(const PUBLIC_SUFFIX *s1, const PUBLIC_SUFFIX *s2)
{
	int n;

	if ((n = s2->nlabels - s1->nlabels))
		return n; // most labels first

	if ((n=s1->length - s2->length))
		return n;  // shorter rules first

	return strcmp(s1->label, s2->label);
}

static void G_GNUC_MGET_NONNULL_ALL _suffix_init(PUBLIC_SUFFIX *suffix, const char *rule, size_t length)
{
	const char *src;
	char *dst;

	suffix->label = suffix->label_buf;

	if (length >= sizeof(suffix->label_buf) - 1) {
		suffix->nlabels = 0;
		error_printf(_("Suffix rule too long (ignored): %s\n"), rule);
		return;
	}

	if (*rule == '*') {
		if (*++rule != '.') {
			suffix->nlabels = 0;
			error_printf(_("Unsupported kind of rule (ignored): %s\n"), rule);
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

int psl_domain_match(const char *domain)
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
	rule = mget_vector_get(_suffixes, 0);
	if (!rule || rule->nlabels < suffix.nlabels - 1)
		return 0;

	rule = mget_vector_get(_suffixes, mget_vector_find(_suffixes, &suffix));
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

		rule = mget_vector_get(_suffixes, mget_vector_find(_suffixes, &suffix));
		if (rule) {
			if (rule->wildcard) {
				// now that we matched a wildcard, we have to check for an exception
				suffix.label = label_bak;
				suffix.length = length_bak;
				suffix.nlabels++;

				rule = mget_vector_get(_suffix_exceptions, mget_vector_find(_suffix_exceptions, &suffix));
				if (rule)
					return 0;

				return 1;
			}
		}
	}

	return 0;
}

int psl_load_file(const char *fname)
{
	PUBLIC_SUFFIX suffix, *suffixp;
	FILE *fp;
	int nsuffixes = 0;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;

	// as of 02.11.2012, the list at http://publicsuffix.org/list/ contains ~6000 rules
	// and 40 exceptions.
	if (!_suffixes)
		_suffixes = mget_vector_create(8*1024, -2, (int(*)(const void *, const void *))_suffix_compare);
	if (!_suffix_exceptions)
		_suffix_exceptions = mget_vector_create(64, -2, (int(*)(const void *, const void *))_suffix_compare);

	if ((fp = fopen(fname, "r"))) {
		while ((buflen = mget_getline(&buf, &bufsize, fp)) >= 0) {
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
				_suffix_init(&suffix, p + 1, linep - p - 1);
				suffixp = mget_vector_get(_suffix_exceptions, mget_vector_add(_suffix_exceptions, &suffix, sizeof(suffix)));
			} else {
				_suffix_init(&suffix, p, linep - p);
				suffixp = mget_vector_get(_suffixes, mget_vector_add(_suffixes, &suffix, sizeof(suffix)));
			}

			if (suffixp)
				suffixp->label = suffixp->label_buf; // set label to changed address

			nsuffixes++;;
		}

		xfree(buf);
		fclose(fp);

		mget_vector_sort(_suffix_exceptions);
		mget_vector_sort(_suffixes);

	} else
		error_printf(_("Failed to open public suffix file '%s'\n"), fname);

	return nsuffixes;
}

/*
static int cookie_free_public_suffix(PUBLIC_SUFFIX *suffix)
{
	return 0;
}
*/

void psl_free(void)
{
	mget_vector_free(&_suffixes);
	mget_vector_free(&_suffix_exceptions);
}

static int
	ok,
	failed;

static void test_cookies(void)
{
	static const struct test_data {
		const char
			*uri,
			*set_cookie,
			*name, *value, *domain, *path, *expires;
		unsigned int
			domain_dot : 1, // for compatibility with Netscape cookie format
			normalized : 1,
			persistent : 1,
			host_only : 1,
			secure_only : 1, // cookie should be used over secure connections only (TLS/HTTPS)
			http_only : 1; // just use the cookie via HTTP/HTTPS protocol
		int
			result;
	} test_data[] = {
		{	// allowed cookie
			"www.example.com",
			"ID=65=abcd; expires=Tuesday, 07-May-2013 07:48:53 GMT; path=/; domain=.example.com; HttpOnly",
			"ID", "65=abcd", "example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			1, 1, 1, 0, 0, 1,
			1
		},
		{	// allowed cookie ANSI C's asctime format
			"www.example.com",
			"ID=65=abcd; expires=Tue May 07 07:48:53 2013; path=/; domain=.example.com",
			"ID", "65=abcd", "example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			1, 1, 1, 0, 0, 0,
			1
		},
		{	// allowed cookie without path
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; domain=.example.com",
			"ID", "65=abcd", "example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			1, 1, 1, 0, 0, 0,
			1
		},
		{	// allowed cookie without domain
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; path=/",
			"ID", "65=abcd", "www.example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			0, 1, 1, 1, 0, 0,
			1
		},
		{	// allowed cookie without domain, path and expires
			"www.example.com",
			"ID=65=abcd",
			"ID", "65=abcd", "www.example.com", "/", "Tue, 07 May 2013 07:48:53 GMT",
			0, 1, 0, 1, 0, 0,
			1
		},
		{	// illegal cookie
			"www.example.com",
			"ID=65=abcd; expires=Tue, 07-May-2013 07:48:53 GMT; path=/; domain=.example.org",
			"ID", "65=abcd", "example.org", "/", "Tue, 07 May 2013 07:48:53 GMT",
			1, 0, 1, 0, 0, 0,
			0
		},
		{	// supercookie, not accepted by normalization (rule 'com')
			"www.example.com",
			"ID=65=abcd; expires=Mon, 29-Feb-2016 07:48:54 GMT; path=/; domain=.com; HttpOnly; Secure",
			"ID", "65=abcd", "com", "/", "Mon, 29 Feb 2016 07:48:54 GMT",
			1, 0, 1, 0, 1, 1,
			0
		},
		{	// supercookie, not accepted by normalization  (rule '*.ar')
			"www.example.ar",
			"ID=65=abcd; expires=Tue, 29-Feb-2000 07:48:55 GMT; path=/; domain=.example.ar",
			"ID", "65=abcd", "example.ar", "/", "Tue, 29 Feb 2000 07:48:55 GMT",
			1, 0, 1, 0, 0, 0,
			0
		},
		{	// exception rule '!educ.ar', accepted by normalization
			"www.educ.ar",
			"ID=65=abcd; path=/; domain=.educ.ar",
			"ID", "65=abcd", "educ.ar", "/", NULL,
			1, 1, 0, 0, 0, 0,
			1
		},
	};
	unsigned it;

	psl_load_file("../data/effective_tld_names.dat");

	for (it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];

		printf("psl_domain_match(%s)=%d\n", t->domain, psl_domain_match(t->domain));

		ok++;
	}

	psl_free();
}

int main(int argc, const char * const *argv)
{
	// if VALGRIND testing is enabled, we have to call ourselves with valgrind checking
	if (argc == 1) {
		const char *valgrind = getenv("TESTS_VALGRIND");

		if (valgrind && *valgrind) {
			char cmd[strlen(valgrind)+strlen(argv[0])+32];

			snprintf(cmd, sizeof(cmd), "TESTS_VALGRIND="" %s %s", valgrind, argv[0]);
			return system(cmd) != 0;
		}
	}

	test_cookies();

	if (failed) {
		info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}

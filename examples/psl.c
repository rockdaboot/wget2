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
 * Public Suffix List routines (right now experimental)
 *
 * Changelog
 * 19.03.2014  Tim Ruehsen  created from libmget/cookie.c
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
#define countof(a) (sizeof(a)/sizeof(*(a)))

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
} _psl_entry_t;

typedef struct {
	mget_vector_t
		*suffixes,
		*suffix_exceptions;
} psl_ctx_t;

void
	psl_free(psl_ctx_t **psl);
psl_ctx_t *
	psl_load_file(const char *fname);
int
	psl_is_tld(psl_ctx_t *psl, const char *domain);

// by this kind of sorting, we can easily see if a domain matches or not (match = supercookie !)

static int G_GNUC_MGET_NONNULL_ALL _suffix_compare(const _psl_entry_t *s1, const _psl_entry_t *s2)
{
	int n;

	if ((n = s2->nlabels - s1->nlabels))
		return n; // most labels first

	if ((n=s1->length - s2->length))
		return n;  // shorter rules first

	return strcmp(s1->label, s2->label);
}

static void G_GNUC_MGET_NONNULL_ALL _suffix_init(_psl_entry_t *suffix, const char *rule, size_t length)
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

int psl_is_tld(psl_ctx_t *psl, const char *domain)
{
	_psl_entry_t suffix, *rule;
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
	rule = mget_vector_get(psl->suffixes, 0);
	if (!rule || rule->nlabels < suffix.nlabels - 1)
		return 0;

	rule = mget_vector_get(psl->suffixes, mget_vector_find(psl->suffixes, &suffix));
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

		rule = mget_vector_get(psl->suffixes, mget_vector_find(psl->suffixes, &suffix));
		if (rule) {
			if (rule->wildcard) {
				// now that we matched a wildcard, we have to check for an exception
				suffix.label = label_bak;
				suffix.length = length_bak;
				suffix.nlabels++;

				if (mget_vector_get(psl->suffix_exceptions, mget_vector_find(psl->suffix_exceptions, &suffix)) != 0)
					return 0;

				return 1;
			}
		}
	}

	return 0;
}

psl_ctx_t *psl_load_file(const char *fname)
{
	psl_ctx_t *psl;
	_psl_entry_t suffix, *suffixp;
	FILE *fp;
	int nsuffixes = 0;
	char *buf = NULL, *linep, *p;
	size_t bufsize = 0;
	ssize_t buflen;

	if (!(psl = calloc(1, sizeof(psl_ctx_t))))
		return NULL;

	// as of 02.11.2012, the list at http://publicsuffix.org/list/ contains ~6000 rules and 40 exceptions.
	// as of 19.02.2014, the list at http://publicsuffix.org/list/ contains ~6500 rules and 19 exceptions.
	if (psl->suffixes)
		psl->suffixes = mget_vector_create(8*1024, -2, (int(*)(const void *, const void *))_suffix_compare);
	if (psl->suffix_exceptions)
		psl->suffix_exceptions = mget_vector_create(64, -2, (int(*)(const void *, const void *))_suffix_compare);

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
				_suffix_init(&suffix, p + 1, linep - p - 1);
				suffixp = mget_vector_get(psl->suffix_exceptions, mget_vector_add(psl->suffix_exceptions, &suffix, sizeof(suffix)));
			} else {
				_suffix_init(&suffix, p, linep - p);
				suffixp = mget_vector_get(psl->suffixes, mget_vector_add(psl->suffixes, &suffix, sizeof(suffix)));
			}

			if (suffixp)
				suffixp->label = suffixp->label_buf; // set label to changed address

			nsuffixes++;;
		}

		free(buf);
		fclose(fp);

		mget_vector_sort(psl->suffix_exceptions);
		mget_vector_sort(psl->suffixes);

	} else
		error_printf(_("Failed to open PSL file '%s'\n"), fname);

	return nsuffixes;
}

void psl_free(psl_ctx_t **psl)
{
	if (psl && *psl) {
		mget_vector_free(&(*psl)->suffixes);
		mget_vector_free(&(*psl)->suffix_exceptions);
		free(*psl);
		*psl = NULL;
	}
}

static int
	ok,
	failed;

static void test_cookies(void)
{
	static const struct test_data {
		const char
			*domain;
		int
			result;
	} test_data[] = {
		{ "www.example.com", 0 },
		{ "com.ar", 1 },
		{ "www.com.ar", 0 },
		{ "cc.ar.us", 1 },
		{ ".cc.ar.us", 1 },
		{ "www.cc.ar.us", 0 },
		{ "www.ck", 0 }, // exception from *.ck
		{ "abc.www.ck", 0 },
		{ "xxx.ck", 1 },
		{ "www.xxx.ck", 0 },
	};
	unsigned it;
	psl_ctx_t *psl;

	psl = psl_load_file("../data/effective_tld_names.dat");

	for (it = 0; it < countof(test_data); it++) {
		const struct test_data *t = &test_data[it];
		int result = psl_is_tld(t->domain);

		if (result == t->result) {
			ok++;
		} else {
			failed++;
			printf("psl_is_tld(%s)=%d (expected %d)\n", t->domain, result, t->result);
		}
	}

	psl_free(&psl);
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

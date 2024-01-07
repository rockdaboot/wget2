/*
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
 * .netrc routines
 *
 * Changelog
 * 01.11.2015  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include <wget.h>
#include "private.h"

struct wget_netrc_db_st {
	wget_hashmap *
		machines;
};

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
WGET_GCC_PURE
static unsigned int hash_netrc(const wget_netrc *netrc)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)netrc->host; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

WGET_GCC_NONNULL_ALL WGET_GCC_PURE
static int compare_netrc(const wget_netrc *h1, const wget_netrc *h2)
{
	return wget_strcmp(h1->host, h2->host);
}

wget_netrc *wget_netrc_init(wget_netrc *netrc)
{
	if (!netrc) {
		if (!(netrc = wget_calloc(1, sizeof(wget_netrc))))
			return NULL;
	} else
		memset(netrc, 0, sizeof(*netrc));

	return netrc;
}

void wget_netrc_deinit(wget_netrc *netrc)
{
	if (netrc) {
		xfree(netrc->host);
		xfree(netrc->login);
		xfree(netrc->password);
	}
}

void wget_netrc_free(wget_netrc *netrc)
{
	if (netrc) {
		wget_netrc_deinit(netrc);
		xfree(netrc);
	}
}

wget_netrc *wget_netrc_new(const char *machine, const char *login, const char *password)
{
	wget_netrc *netrc = wget_netrc_init(NULL);

	if (netrc) {
		netrc->host = wget_strdup(machine);
		netrc->login = wget_strdup(login);
		netrc->password = wget_strdup(password);
	}

	return netrc;
}

wget_netrc *wget_netrc_get(const wget_netrc_db *netrc_db, const char *host)
{
	if (netrc_db) {
		wget_netrc netrc, *netrcp;

		// look for an exact match
		netrc.host = host;

		if (wget_hashmap_get(netrc_db->machines, &netrc, &netrcp))
			return netrcp;
	}

	return NULL;
}

wget_netrc_db *wget_netrc_db_init(wget_netrc_db *netrc_db)
{
	wget_hashmap *machines = wget_hashmap_create(16, (wget_hashmap_hash_fn *) hash_netrc, (wget_hashmap_compare_fn *) compare_netrc);

	if (!machines)
		return NULL;

	if (!netrc_db) {
		if (!(netrc_db = wget_calloc(1, sizeof(wget_netrc_db)))) {
			wget_hashmap_free(&machines);
			return NULL;
		}
	} else
		memset(netrc_db, 0, sizeof(*netrc_db));

	wget_hashmap_set_key_destructor(machines, (wget_hashmap_key_destructor *) wget_netrc_free);
	wget_hashmap_set_value_destructor(machines, (wget_hashmap_value_destructor *) wget_netrc_free);
	netrc_db->machines = machines;

	return netrc_db;
}

void wget_netrc_db_deinit(wget_netrc_db *netrc_db)
{
	if (netrc_db) {
		wget_hashmap_free(&netrc_db->machines);
	}
}

void wget_netrc_db_free(wget_netrc_db **netrc_db)
{
	if (netrc_db) {
		wget_netrc_db_deinit(*netrc_db);
		xfree(*netrc_db);
	}
}

void wget_netrc_db_add(wget_netrc_db *netrc_db, wget_netrc *netrc)
{
	if (!netrc)
		return;

	if (!netrc_db) {
		wget_netrc_free(netrc);
		return;
	}

	// key and value are the same to make wget_hashmap_get() return old 'netrc'
	debug_printf("add .netrc %s (login=%s, password=*)\n", netrc->host, netrc->login);
	wget_hashmap_put(netrc_db->machines, netrc, netrc);
	// no need to free anything here
}

static const char *unescape_password(const char *p, size_t n)
{
	char *dst = wget_malloc(n + 1), *bufp = dst;
	if (!dst) {
		return dst;
	}

	for (; n; n--) {
		if (*p == '\\')
			p++;
		*bufp++ = *p++;
	}
	*bufp = 0;

	return dst;
}

// load the .netrc file
// not thread-save
int wget_netrc_db_load(wget_netrc_db *netrc_db, const char *fname)
{
	FILE *fp;

	if (!netrc_db || !fname || !*fname)
		return WGET_E_INVALID;

	if (!(fp = fopen(fname, "r")))
		return WGET_E_OPEN;

	wget_netrc netrc;
	char *buf = NULL, *linep, *p, *key = NULL;
	size_t bufsize = 0;
	ssize_t buflen;
	int nentries = 0;
	bool in_macdef = 0, in_machine = 0, quoted = 0;

	while ((buflen = wget_getline(&buf, &bufsize, fp)) >= 0) {
		linep = buf;

		while (isspace(*linep)) linep++; // ignore leading whitespace

		if (*linep == '#')
			continue; // skip comments

		// strip off \r\n
		while (buflen > 0 && (buf[buflen] == '\n' || buf[buflen] == '\r'))
			buf[--buflen] = 0;

		if (!*linep) {
			// empty lines reset macro processing
			in_macdef = 0;
			continue;
		} else if (in_macdef)
			continue; // still processing 'macdef' macro

		// now we expect key value pairs, e.g.: machine example.com
		do {
			xfree(key);
			while (isspace(*linep)) linep++;
			for (p = linep; *linep && !isspace(*linep);) linep++;

			if (!(key = wget_strmemdup(p, linep - p))) {
				xfree(buf);
				fclose(fp);
				return WGET_E_MEMORY;
			}

			if (!strcmp(key, "machine") || !strcmp(key, "default")) {
				if (in_machine)
					wget_netrc_db_add(netrc_db, wget_memdup(&netrc, sizeof(netrc)));

				wget_netrc_init(&netrc);
				in_machine = 1;

				if (!strcmp(key, "default")) {
					netrc.host = wget_strdup("default");
					continue;
				}
			} else if (!in_machine)
				continue; // token outside of machine or default

			while (isspace(*linep)) linep++;
			if (*linep == '\"') {
				quoted = 1;
				linep++;
			}

			int escaped = 0;
			for (p = linep; *linep && (quoted ? *linep != '\"' : !isspace(*linep));) {
				if (*linep == '\\') {
					escaped++;
					linep++;
				}
				linep++;
			}

			if (!strcmp(key, "machine")) {
				if (!netrc.host)
					netrc.host = wget_strmemdup(p, linep - p);
			} else if (!strcmp(key, "login") || !strcmp(key, "user")) {
            // "user" is for fetchmail compatibility
				if (!netrc.login)
					netrc.login = wget_strmemdup(p, linep - p);
			} else if (!strcmp(key, "password") || !strcmp(key, "passwd")) {
            // "passwd" is for fetchmail compatibility
				if (!netrc.password) {
					if (!escaped)
						 netrc.password = wget_strmemdup(p, linep - p);
					else
						netrc.password = unescape_password(p, linep - p - escaped);
				}
			} else if (!strcmp(key, "port")) { // GNU extension
				netrc.port = (uint16_t) atoi(p);
			} else if (!strcmp(key, "force")) { // GNU extension
				netrc.force = !wget_strncasecmp_ascii("yes", p, 3);
			} else if (!strcmp(key, "macdef")) {
				in_macdef = 1; // the above code skips until next empty line
			}

			if (quoted && *linep == '\"')
				linep++;

		} while (*linep);

		xfree(key);
	}

	if (in_machine)
		wget_netrc_db_add(netrc_db, wget_memdup(&netrc, sizeof(netrc)));

	xfree(buf);
	fclose(fp);

	nentries = wget_hashmap_size(netrc_db->machines);

	debug_printf("loaded %d .netrc %s\n", nentries, nentries != 1 ? "entries" : "entry");

	return nentries;
}

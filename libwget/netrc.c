/*
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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

struct _wget_netrc_db_st {
	wget_hashmap_t *
		machines;
};

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int G_GNUC_WGET_PURE _hash_netrc(const wget_netrc_t *netrc)
{
	unsigned int hash = 0;
	const unsigned char *p;

	for (p = (unsigned char *)netrc->host; *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static int G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PURE _compare_netrc(const wget_netrc_t *h1, const wget_netrc_t *h2)
{
	return wget_strcmp(h1->host, h2->host);
}

wget_netrc_t *wget_netrc_init(wget_netrc_t *netrc)
{
	if (!netrc)
		netrc = xmalloc(sizeof(wget_netrc_t));

	memset(netrc, 0, sizeof(*netrc));

	return netrc;
}

void wget_netrc_deinit(wget_netrc_t *netrc)
{
	if (netrc) {
		xfree(netrc->host);
		xfree(netrc->login);
		xfree(netrc->password);
	}
}

void wget_netrc_free(wget_netrc_t *netrc)
{
	if (netrc) {
		wget_netrc_deinit(netrc);
		xfree(netrc);
	}
}

wget_netrc_t *wget_netrc_new(const char *machine, const char *login, const char *password)
{
	wget_netrc_t *netrc = wget_netrc_init(NULL);

	netrc->host = wget_strdup(machine);
	netrc->login = wget_strdup(login);
	netrc->password = wget_strdup(password);

	return netrc;
}

wget_netrc_t *wget_netrc_get(const wget_netrc_db_t *netrc_db, const char *host)
{
	if (netrc_db) {
		wget_netrc_t netrc;

		// look for an exact match
		netrc.host = host;
		return wget_hashmap_get(netrc_db->machines, &netrc);
	}

	return NULL;
}

wget_netrc_db_t *wget_netrc_db_init(wget_netrc_db_t *netrc_db)
{
	if (!netrc_db)
		netrc_db = xmalloc(sizeof(wget_netrc_db_t));

	memset(netrc_db, 0, sizeof(*netrc_db));

	netrc_db->machines = wget_hashmap_create(16, (wget_hashmap_hash_t)_hash_netrc, (wget_hashmap_compare_t)_compare_netrc);
	wget_hashmap_set_key_destructor(netrc_db->machines, (wget_hashmap_key_destructor_t)wget_netrc_free);
	wget_hashmap_set_value_destructor(netrc_db->machines, (wget_hashmap_value_destructor_t)wget_netrc_free);

	return netrc_db;
}

void wget_netrc_db_deinit(wget_netrc_db_t *netrc_db)
{
	if (netrc_db) {
		wget_hashmap_free(&netrc_db->machines);
	}
}

void wget_netrc_db_free(wget_netrc_db_t **netrc_db)
{
	if (netrc_db) {
		wget_netrc_db_deinit(*netrc_db);
		xfree(*netrc_db);
	}
}

void wget_netrc_db_add(wget_netrc_db_t *netrc_db, wget_netrc_t *netrc)
{
	if (!netrc)
		return;

	if (!netrc_db) {
		wget_netrc_free(netrc);
		return;
	}

	// key and value are the same to make wget_hashmap_get() return old 'netrc'
	debug_printf("add .netrc %s (login=%s, password=*)\n", netrc->host, netrc->login);
	wget_hashmap_put_noalloc(netrc_db->machines, netrc, netrc);
	// no need to free anything here
}

// load the .netrc file
// not thread-save

int wget_netrc_db_load(wget_netrc_db_t *netrc_db, const char *fname)
{
	wget_netrc_t netrc;
	FILE *fp;
	char *buf = NULL, *linep, *p, *key = NULL;
	size_t bufsize = 0;
	ssize_t buflen;
	int nentries = 0, in_macdef = 0, in_machine = 0;

	if (!netrc_db || !fname || !*fname)
		return -1;

	if ((fp = fopen(fname, "r"))) {
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
				key = wget_strmemdup(p, linep - p);

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
				for (p = linep; *linep && !isspace(*linep);) linep++;

				if (!strcmp(key, "machine")) {
					if (!netrc.host)
						netrc.host = wget_strmemdup(p, linep - p);
				} else if (!strcmp(key, "login")) {
					if (!netrc.login)
						netrc.login = wget_strmemdup(p, linep - p);
				} else if (!strcmp(key, "password")) {
					if (!netrc.password)
						netrc.password = wget_strmemdup(p, linep - p);
				} else if (!strcmp(key, "macdef")) {
					in_macdef = 1; // the above code skips until next empty line
				}
			} while (*linep);

			xfree(key);
		}

		if (in_machine)
			wget_netrc_db_add(netrc_db, wget_memdup(&netrc, sizeof(netrc)));

		xfree(buf);
		fclose(fp);

		nentries = wget_hashmap_size(netrc_db->machines);

		debug_printf("loaded %d .netrc %s\n", nentries, nentries != 1 ? "entries" : "entry");
	} else if (errno != ENOENT)
		error_printf(_("Failed to open .netrc file '%s' (%d)\n"), fname, errno);

	return nentries;
}

/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * routines to parse robots.txt
 *
 * Changelog
 * 28.09.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <strings.h>
#include <string.h>
#include <ctype.h>

#include <libwget.h>
#include "private.h"

static void _free_path(ROBOTS_PATH *path)
{
	xfree(path->path);
}

ROBOTS *wget_robots_parse(const char *data)
{
	ROBOTS *robots;
	ROBOTS_PATH path;
	int collect = 0;
	const char *p;

	if (!data || !*data)
		return NULL;

	robots = xcalloc(1, sizeof (ROBOTS));

	do {
		if (collect < 2 && !strncasecmp(data, "User-agent:", 11)) {
			if (!collect) {
				for (data += 11; *data == ' ' || *data == '\t'; data++);
				if (!strncasecmp(data, "wget", 4)) {
					collect = 1;
				}
				else if (*data == '*') {
					collect = 1;
				}
			} else
				collect = 2;
		}
		else if (collect == 1 && !strncasecmp(data, "Disallow:", 9)) {
			for (data += 9; *data == ' ' || *data == '\t'; data++);
			if (*data == '\r' || *data == '\n' || !*data) {
				// all allowed
				wget_vector_free(&robots->paths);
				collect = 2;
			} else {
				if (!robots->paths) {
					robots->paths = wget_vector_create(32, -2, NULL);
					wget_vector_set_destructor(robots->paths, (void(*)(void *))_free_path);
				}
				for (p = data; !isspace(*p); p++);
				path.len = p - data;
				path.path = strndup(data, path.len);
				wget_vector_add(robots->paths, &path, sizeof(path));
			}
		}
		else if (!strncasecmp(data, "Sitemap:", 8)) {
			for (data += 8; *data==' ' || *data == '\t'; data++);
			for (p = data; !isspace(*p); p++);

			if (!robots->sitemaps)
				robots->sitemaps = wget_vector_create(4, -2, NULL);
			wget_vector_add_noalloc(robots->sitemaps, strndup(data, p - data));
		}

		if ((data = strchr(data, '\n')))
			data++; // point to next line
	} while (data && *data);

/*
	for (int it = 0; it < wget_vector_size(robots->paths); it++) {
		ROBOTS_PATH *path = wget_vector_get(robots->paths, it);
		info_printf("path '%s'\n", path->path);
	}
	for (int it = 0; it < wget_vector_size(robots->sitemaps); it++) {
		const char *sitemap = wget_vector_get(robots->sitemaps, it);
		info_printf("sitemap '%s'\n", sitemap);
	}
*/

	return robots;
}

void wget_robots_free(ROBOTS **robots)
{
	if (robots && *robots) {
		wget_vector_free(&(*robots)->paths);
		wget_vector_free(&(*robots)->sitemaps);
	}
}

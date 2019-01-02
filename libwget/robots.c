/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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
 * routines to parse robots.txt
 *
 * Changelog
 * 28.09.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <string.h>
#include <ctype.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Robots Exclusion file parser
 * \defgroup libwget-robots Robots Exclusion file parser
 * @{
 *
 * The purpose of this set of functions is to parse a
 * Robots Exlusion Standard file into a data structure
 * for easy access.
 */

static void _free_path(wget_string_t *path)
{
	xfree(path->p);
}

/**
 * \param[in] data Memory with robots.txt content (with trailing 0-byte)
 * \param[in] client Name of the client / user-agent
 * \return Return an allocated ROBOTS structure or NULL on error
 *
 * The function parses the robots.txt \p data and returns a ROBOTS structure
 * including a list of the disallowed paths and including a list of the sitemap
 * files.
 *
 * The ROBOTS structure has to be freed by calling wget_robots_free().
 */
wget_robots_t *wget_robots_parse(const char *data, const char *client)
{
	wget_robots_t *robots;
	wget_string_t path;
	size_t client_length = client ? strlen(client) : 0;
	int collect = 0;
	const char *p;

	if (!data || !*data)
		return NULL;

	robots = xcalloc(1, sizeof (wget_robots_t));

	do {
		if (collect < 2 && !wget_strncasecmp_ascii(data, "User-agent:", 11)) {
			if (!collect) {
				for (data += 11; *data == ' ' || *data == '\t'; data++);
				if (client && !wget_strncasecmp_ascii(data, client, client_length)) {
					collect = 1;
				}
				else if (*data == '*') {
					collect = 1;
				}
			} else
				collect = 2;
		}
		else if (collect == 1 && !wget_strncasecmp_ascii(data, "Disallow:", 9)) {
			for (data += 9; *data == ' ' || *data == '\t'; data++);
			if (*data == '\r' || *data == '\n' || !*data) {
				// all allowed
				wget_vector_free(&robots->paths);
				collect = 2;
			} else {
				if (!robots->paths) {
					robots->paths = wget_vector_create(32, NULL);
					wget_vector_set_destructor(robots->paths, (wget_vector_destructor_t)_free_path);
				}
				for (p = data; *p && !isspace(*p); p++);
				path.len = p - data;
				path.p = wget_strmemdup(data, path.len);
				wget_vector_add(robots->paths, &path, sizeof(path));
			}
		}
		else if (!wget_strncasecmp_ascii(data, "Sitemap:", 8)) {
			for (data += 8; *data==' ' || *data == '\t'; data++);
			for (p = data; *p && !isspace(*p); p++);

			if (!robots->sitemaps)
				robots->sitemaps = wget_vector_create(4, NULL);
			wget_vector_add_noalloc(robots->sitemaps, wget_strmemdup(data, p - data));
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

/**
 * \param[in,out] robots Pointer to Pointer to ROBOTS structure
 *
 * wget_robots_free() free's the formerly allocated ROBOTS structure.
 */
void wget_robots_free(wget_robots_t **robots)
{
	if (robots && *robots) {
		wget_vector_free(&(*robots)->paths);
		wget_vector_free(&(*robots)->sitemaps);
		xfree(*robots);
		*robots = NULL;
	}
}

/**@}*/

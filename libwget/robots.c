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
 * routines to parse robots.txt (RFC 9309)
 *
 * Changelog
 * 28.09.2013  Tim Ruehsen  created
 * 15.03.2024  Avinash Sonawane, Tim Ruehsen  updated to RFC 9309 (except for the Allow field)
 *
 */

#include <config.h>

#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Robots Exclusion file parser
 * \defgroup libwget-robots Robots Exclusion file parser
 * @{
 *
 * The purpose of this set of functions is to parse a
 * Robots Exclusion Standard file into a data structure
 * for easy access.
 */

struct wget_robots_st {
	wget_vector
		*paths;    //!< paths found in robots.txt (element: wget_string)
	wget_vector
		*sitemaps; //!< sitemaps found in robots.txt (element: char *)
};

static void path_free(void *path)
{
	wget_string *p = path;

	xfree(p->p);
	xfree(p);
}

static inline void advance_ws(const char **s)
{
	for (; isblank(**s); (*s)++);
}

static bool parse_record_field(const char **data, const char *field, size_t field_length)
{
	advance_ws(data);

	if (wget_strncasecmp_ascii(*data, field, field_length))
		return false;

	*data += field_length;
	advance_ws(data);

	if (**data != ':')
		return false;

	*data += 1;
	advance_ws(data);

	return true;
}
#define parse_record_field(d, f) parse_record_field(d, f, sizeof(f) - 1)


/**
 * \param[in] data Memory with robots.txt content (with trailing 0-byte)
 * \param[in] client Name of the client / user-agent
 * \return Return an allocated wget_robots structure or NULL on error
 *
 * The function parses the robots.txt \p data in accordance to
 * https://www.robotstxt.org/orig.html#format and returns a ROBOTS structure
 * including a list of the disallowed paths and including a list of the sitemap
 * files.
 *
 * The ROBOTS structure has to be freed by calling wget_robots_free().
 */
int wget_robots_parse(wget_robots **_robots, const char *data, const char *client)
{
	wget_robots *robots;
	wget_string path;
	size_t client_length = client ? strlen(client) : 0;
	const char *p;
	bool seek_record_client = false;
	enum record {
		NOT_IN_RECORD,
		/* User-agent:client */
		IN_RECORD_CLIENT,
		/* User-agent:* */
		IN_RECORD_STAR,
		/* Disallow:foo */
		ADDED_DISALLOW,
		NO_MORE_RECORDS
	} state;

	if (!data || !*data || !_robots)
		return WGET_E_INVALID;

	if (!(robots = wget_calloc(1, sizeof(wget_robots))))
		return WGET_E_MEMORY;

	state = NOT_IN_RECORD;
	do {
		if (state != NO_MORE_RECORDS && state != IN_RECORD_CLIENT && parse_record_field(&data, "User-agent")) {
			if (client && !wget_strncasecmp_ascii(data, client, client_length)) {
				if (!seek_record_client)
					wget_vector_free(&robots->paths);
				seek_record_client = true;
				state = IN_RECORD_CLIENT;
			} else if (!seek_record_client && (*data == '*'))
				state = IN_RECORD_STAR;
			else if (state == ADDED_DISALLOW)
				state = NOT_IN_RECORD;
		} else if (state != NO_MORE_RECORDS && state != NOT_IN_RECORD && parse_record_field(&data, "Disallow")) {
			if (!*data || isspace(*data) || *data == '#') {
				// all allowed
				wget_vector_free(&robots->paths);
				if (seek_record_client)
					state = NO_MORE_RECORDS;
				else {
					state = NOT_IN_RECORD;
					seek_record_client = true;
				}
			} else {
				if (!robots->paths) {
					if (!(robots->paths = wget_vector_create(32, NULL)))
						goto oom;
					wget_vector_set_destructor(robots->paths, path_free);
				}
				for (p = data; *p && !isspace(*p) && *p != '#'; p++);
				path.len = p - data;
				if (!(path.p = wget_strmemdup(data, path.len)))
					goto oom;
				if (wget_vector_add_memdup(robots->paths, &path, sizeof(path)) < 0) {
					xfree(path.p);
					goto oom;
				}
				state = ADDED_DISALLOW;
			}
		} else if (parse_record_field(&data, "Sitemap")) {
			for (p = data; *p && !isspace(*p) && *p != '#'; p++);

			if (p > data){
				if (!robots->sitemaps)
					if (!(robots->sitemaps = wget_vector_create(4, NULL)))
						goto oom;

				char *sitemap = wget_strmemdup(data, p - data);
				if (!sitemap)
					goto oom;
				if (wget_vector_add(robots->sitemaps, sitemap) < 0)
					goto oom;
			}
		}

		if ((data = strchr(data, '\n')))
			data++; // point to next line
	} while (data && *data);

/*
	for (int it = 0; it < wget_vector_size(robots->paths); it++) {
		ROBOTS_PATH *path = wget_vector_get(robots->paths, it);
		debug_printf("path '%s'\n", path->path);
	}
	for (int it = 0; it < wget_vector_size(robots->sitemaps); it++) {
		const char *sitemap = wget_vector_get(robots->sitemaps, it);
		debug_printf("sitemap '%s'\n", sitemap);
	}
*/

	*(_robots) = robots;
	return WGET_E_SUCCESS;

oom:
	wget_robots_free(&robots);
	return WGET_E_MEMORY;
}

/**
 * \param[in,out] robots Pointer to Pointer to wget_robots structure
 *
 * wget_robots_free() free's the formerly allocated wget_robots structure.
 */
void wget_robots_free(wget_robots **robots)
{
	if (robots && *robots) {
		wget_vector_free(&(*robots)->paths);
		wget_vector_free(&(*robots)->sitemaps);
		xfree(*robots);
		*robots = NULL;
	}
}

/**
 * @param robots Pointer to instance of wget_robots
 * @return Returns the number of paths listed in \p robots
 */
int wget_robots_get_path_count(wget_robots *robots)
{
	if (robots)
		return wget_vector_size(robots->paths);

	return 0;
}

/**
 * @param robots Pointer to instance of wget_robots
 * @param index Index of the wanted path
 * @return Returns the path at \p index or NULL
 */
wget_string *wget_robots_get_path(wget_robots *robots, int index)
{
	if (robots && robots->paths)
		return wget_vector_get(robots->paths, index);

	return NULL;
}

/**
 * @param robots Pointer to instance of wget_robots
 * @return Returns the number of sitemaps listed in \p robots
 */
int wget_robots_get_sitemap_count(wget_robots *robots)
{
	if (robots)
		return wget_vector_size(robots->sitemaps);

	return 0;
}

/**
 * @param robots Pointer to instance of wget_robots
 * @param index Index of the wanted sitemap URL
 * @return Returns the sitemap URL at \p index or NULL
 */
const char *wget_robots_get_sitemap(wget_robots *robots, int index)
{
	if (robots && robots->sitemaps)
		return wget_vector_get(robots->sitemaps, index);

	return NULL;
}

/**@}*/

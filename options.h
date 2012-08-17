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
 * Header file for option routines
 *
 * Changelog
 * 12.06.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_OPTIONS_H
#define _MGET_OPTIONS_H

#include <stdarg.h>

#include "mget.h"

struct config {
	int
		connect_timeout, // ms
		dns_timeout, // ms
		read_timeout, // ms
		max_redirect,
		num_threads;
	const char
		*logfile,
		*logfile_append,
		*user_agent,
		*output_document;
	char
		dns_caching,
		check_certificate,
		span_hosts,
		recursive,
		verbose,
		quiet,
		debug;
};

extern struct config
	config;

int
	init(int argc, const char *const *argv);

#endif /* _MGET_OPTIONS_H */

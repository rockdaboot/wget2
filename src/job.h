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
 * Header file for job routines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_JOB_H
#define _MGET_JOB_H

#include <libmget.h>

#include "host.h"

// file part to download
typedef struct {
	off_t
		position;
	off_t
		length;
	int
		id;
	char
		inuse,
		done;
} PART;

struct JOB {
	MGET_IRI
		*iri,
		*referer;

	// Metalink information
	MGET_METALINK
		*metalink;

	MGET_VECTOR
		*parts, // parts to download
		*deferred; // IRIs that need to wait for this job to be done (while downloading robots.txt)
	HOST
		*host;
	const char
		*local_filename;
	int
		level, // current recursion level
		redirection_level, // number of redirections occurred to create this job
		mirror_pos, // where to look up the next (metalink) mirror to use
		piece_pos; // where to look up the next (metalink) piece to download
	char
		inuse,
		sitemap; // URL is a sitemap to be scanned in recursive mode
};

JOB
	*queue_add(MGET_IRI *iri);
PART
	*job_add_part(JOB *job, PART *part);
int
	queue_empty(void) G_GNUC_MGET_PURE,
	queue_get(JOB **job_out, PART **part_out),
	job_validate_file(JOB *job);
void
	queue_print(void),
	job_create_parts(JOB *job),
	job_free(JOB *job),
//	job_resume(JOB *job),
	queue_del(JOB *job),
	queue_free(void);


#endif /* _MGET_JOB_H */

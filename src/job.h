/*
 * Copyright(c) 2012 Tim Ruehsen
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
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for job routines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _WGET_JOB_H
#define _WGET_JOB_H

#include <libwget.h>

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
	wget_iri_t
		*iri,
		*referer;

	// Metalink information
	wget_metalink_t
		*metalink;

	wget_vector_t
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
		inuse, // if job is already in use by another downloader thread
		sitemap, // URL is a sitemap to be scanned in recursive mode
		head_first; // first check mime type by using a HEAD request
};

JOB
	*job_init(JOB *job, wget_iri_t *iri),
	*queue_add_job(JOB *job);
PART
	*job_add_part(JOB *job, PART *part);
int
	queue_size(void) G_GNUC_WGET_PURE,
	queue_empty(void) G_GNUC_WGET_PURE,
	queue_get(JOB **job_out, PART **part_out),
	job_validate_file(JOB *job);
void
	queue_print(void),
	job_create_parts(JOB *job),
	job_free(JOB *job),
//	job_resume(JOB *job),
	queue_del(JOB *job),
	queue_free(void);


#endif /* _WGET_JOB_H */

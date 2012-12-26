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

#include "iri.h"
#include "vector.h"

typedef struct {
	IRI
		*iri;
	int
		priority;
	char
		location[3];
} MIRROR;

typedef struct {
	char
		type[16],
		hash_hex[128+1];
} HASH;

// Metalink piece, for checksumming after download
typedef struct {
	HASH
		hash;
	off_t
		position;
	off_t
		length;
} PIECE;

// file part to download
typedef struct {
	off_t
		position;
	off_t
		length;
	char
		inuse,
		done;
} PART;

typedef struct {
	IRI
		*iri,
		*referer;

	// Metalink information
	VECTOR
		*mirrors,
		*hashes, // checksums of complete file
		*pieces, // checksums of smaller pieces of the file
		*parts; // parts to download
	const char
		*name,
		*local_filename;
	off_t
		size; // total size of the file
	int
		mirror_pos, // where to look up the next mirror to use
		piece_pos, // where to look up the next piece to download
		redirection_level; // number of redirections occurred to create this job
	char
		inuse,
		hash_ok; // checksum of complete file is ok
} JOB;

JOB
	*queue_add(IRI *iri);
PART
	*job_add_part(JOB *job, PART *part);
int
	queue_empty(void) PURE,
	queue_get(JOB **job_out, PART **part_out);
void
	job_create_parts(JOB *job),
	job_sort_mirrors(JOB *job),
	job_free(JOB *job),
	job_validate_file(JOB *job),
//	job_resume(JOB *job),
	queue_del(JOB *job),
	queue_free(void);


#endif /* _MGET_JOB_H */

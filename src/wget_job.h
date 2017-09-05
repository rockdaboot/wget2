/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
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

#include <sys/types.h> // for off_t

#include <wget.h>
#include "wget_host.h"

// file part to download
typedef struct {
	off_t
		position;
	off_t
		length;
	int
		id;
	wget_thread_t
		used_by;
	unsigned char
		inuse : 1,
		done : 1;
} PART;

typedef struct DOWNLOADER DOWNLOADER;

struct JOB {
	wget_iri_t
		*iri,
		*original_url,
		*referer;

	// Metalink information
	wget_metalink_t
		*metalink;

	wget_vector_t
		*challenges; // challenges from 401 response

	wget_vector_t
		*proxy_challenges; // challenges from 407 response (proxy)

	wget_vector_t
		*parts; // parts to download
	HOST
		*host;
	const char
		*local_filename;
	PART
		*part; // current chunk to download
	DOWNLOADER
		*downloader;

	wget_thread_t
		used_by; // keep track of who uses this job, for host_release_jobs()
	int
		level, // current recursion level
		redirection_level, // number of redirections occurred to create this job
		auth_failure_count, // number of times server has returned a 401 response
		mirror_pos, // where to look up the next (metalink) mirror to use
		piece_pos; // where to look up the next (metalink) piece to download
	bool
		challenges_alloc; // Indicate whether the challenges vector is owned by the JOB
	unsigned char
		inuse : 1, // if job is already in use, 'used_by' holds the thread id of the downloader
		sitemap : 1, // URL is a sitemap to be scanned in recursive mode
		robotstxt : 1, // URL is a robots.txt to be scanned
		head_first : 1, // first check mime type by using a HEAD request
		requested_by_user : 1, // download even if disallowed by robots.txt
		ignore_patterns : 1; // Ignore accept/reject patterns
};

struct DOWNLOADER {
	wget_thread_t
		tid;
	JOB
		*job;
	wget_http_connection_t
		*conn;
	char
		*buf;
	size_t
		bufsize;
	int
		id;
	wget_thread_cond_t
		cond;
	char
		final_error;
};

JOB *job_init(JOB *job, wget_iri_t *iri) G_GNUC_WGET_NONNULL((2));
int job_validate_file(JOB *job) G_GNUC_WGET_NONNULL((1));
void job_create_parts(JOB *job) G_GNUC_WGET_NONNULL((1));
void job_free(JOB *job) G_GNUC_WGET_NONNULL((1));

#endif /* _WGET_JOB_H */

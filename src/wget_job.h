/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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

#ifndef SRC_WGET_JOB_H
#define SRC_WGET_JOB_H

#include <sys/types.h> // for off_t

#include <wget.h>
#include "wget_blacklist.h"
#include "wget_host.h"

// file part to download
typedef struct {
	off_t
		position;
	off_t
		length;
	int
		id;
	wget_thread_id
		used_by;
	bool
		inuse : 1,
		done : 1;
} PART;

typedef struct DOWNLOADER DOWNLOADER;

struct JOB {
	const wget_iri
		*iri,
		*original_url,
		*referer;

	// Metalink information
	wget_metalink
		*metalink;

	wget_vector
		*challenges; // challenges from 401 response

	wget_vector
		*proxy_challenges; // challenges from 407 response (proxy)

	wget_vector
		*parts; // parts to download

	wget_list
		*remaining_sig_ext; // Signature extensions yet to be tried.

	HOST
		*host;
	const blacklist_entry
		*blacklist_entry;
	char
		*sig_filename, // Signature information. Meaning depends on sig_req.
		*sig_req; // The base URI for the file that we need to verify.
	PART
		*part; // current chunk to download
	DOWNLOADER
		*downloader;

	wget_thread_id
		used_by; // keep track of who uses this job, for host_release_jobs()
	unsigned long long
		id, // each job an unique ID value
		parent_id; // parent job id for recursive mode
	long long
		retry_ts; // timestamp of earliest retry in milliseconds
	int
		level, // current recursion level
		redirection_level, // number of redirections occurred to create this job
		auth_failure_count, // number of times server has returned a 401 response
		mirror_pos, // where to look up the next (metalink) mirror to use
		piece_pos, // where to look up the next (metalink) piece to download
		failures; // if failures reach config.tries, the job finally failed and is removed
	bool
		challenges_alloc : 1, // Indicate whether the challenges vector is owned by the JOB
		inuse : 1, // if job is already in use, 'used_by' holds the thread id of the downloader
		done : 1, // if job has to be retried, else it is done and can be removed (used by the downloader threads)
		sitemap : 1, // URL is a sitemap to be scanned in recursive mode
		robotstxt : 1, // URL is a robots.txt to be scanned
		head_first : 1, // first send a HEAD request
		requested_by_user : 1, // download even if disallowed by robots.txt
		ignore_patterns : 1, // Ignore accept/reject patterns
		http_fallback : 1, // When true, we try again on error, using HTTP (instead of HTTPS)
		recursive_send_head : 1, // Indicate whether the HEAD request is sent by the recursive mode
		redirect_get : 1; // Indicate whether to use GET method for redirection request
};

struct DOWNLOADER {
	wget_thread
		thread;
	JOB
		*job;
	wget_http_connection
		*conn;
	char
		*buf;
	size_t
		bufsize;
	int
		id;
	wget_thread_cond
		cond;
	bool
		final_error : 1;
};

JOB *job_init(JOB *job, blacklist_entry *blacklistp, bool http_fallback) WGET_GCC_NONNULL((2));
int job_validate_file(JOB *job) WGET_GCC_NONNULL((1));
void job_create_parts(JOB *job) WGET_GCC_NONNULL((1));
void job_free(JOB *job) WGET_GCC_NONNULL((1));

#endif /* SRC_WGET_JOB_H */

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
 * Header file for HOST stuff
 *
 * Changelog
 * 10.09.2013  Tim Ruehsen  created
 *
 */

#ifndef _WGET_HOST_H
#define _WGET_HOST_H

#include <wget.h>
#include <stdbool.h>

struct JOB;
typedef struct JOB JOB;

struct DOC;
typedef struct DOC DOC;

typedef struct {
	wget_iri_t
		*iri;
	DOC *doc;
	bool
		redirect;
	wget_vector_t
		*children;
} TREE_DOCS;

// everything host/domain specific should go here
typedef struct {
	const char
		*scheme,
		*host;
	JOB
		*robot_job; // special job for downloading robots.txt (before anything else)
	wget_robots_t
		*robots;
	wget_list_t
		*queue; // host specific job queue
	wget_hashmap_t
		*host_docs;
	wget_hashmap_t
		*tree_docs;
	TREE_DOCS
		*root,
		*robot;
	long long
		retry_ts; // timestamp of earliest retry in milliseconds
	int
		qsize, // number of jobs in queue
		failures; // number of consequent connection failures
	uint16_t
		port;
	bool
		blocked : 1; // host may be blocked after too many errors or even one final error
} HOST;

typedef struct {
	int
		http_status;
	wget_hashmap_t
		*docs;
} HOST_DOCS;

struct DOC {
	wget_iri_t
		*iri;
	int
		status;
	long long
		size_downloaded,
		size_decompressed;
	bool
		head_req;
	char
		encoding;
	long long
		request_start; // Milli timestamp initial request went out
	long long
		response_end; // Milli timestamp that final response read in
	long long
		initial_response_duration; // Number of millis between initial request, and first bytes back
	bool
		is_sig; //!< Is this DOC a signature for a file?
	int
		valid_sigs, //!< Number of valid GPG signatures inside the doc. Meaningless if !is_sig.
		invalid_sigs, //!< Number of invalid GPG signatures inside the dov. Meaningless if !is_sig.
		missing_sigs, //!< Number of GPG signatures with missing public keys. Meaningless if !is_sig.
		bad_sigs; //!< Number of bad GPG signatures. Meaningless if !is_sig.

};

struct site_stats {
	wget_buffer_t
		*buf;
	FILE
		*fp;
	int
		level;
};

struct site_stats_cvs_json {
	wget_buffer_t
		*buf;
	FILE
		*fp;
	int
		id,
		parent_id,
		ntabs;
	HOST
		*host;
	wget_stats_format_t
		format;
};

struct json_stats {
	wget_buffer_t
		*buf;
	bool
		last;
	int
		ntabs;
};

void host_init(void);
void host_exit(void);

HOST *host_add(wget_iri_t *iri) G_GNUC_WGET_NONNULL((1));
HOST *host_get(wget_iri_t *iri) G_GNUC_WGET_NONNULL((1));

JOB *host_get_job(HOST *host, long long *pause);
void host_add_job(HOST *host, const JOB *job) G_GNUC_WGET_NONNULL((1,2));
void host_add_robotstxt_job(HOST *host, wget_iri_t *iri, bool http_fallback) G_GNUC_WGET_NONNULL((1,2));
void host_release_jobs(HOST *host);
void host_remove_job(HOST *host, JOB *job) G_GNUC_WGET_NONNULL((1,2));
void host_queue_free(HOST *host) G_GNUC_WGET_NONNULL((1));
void hosts_free(void);
void host_increase_failure(HOST *host) G_GNUC_WGET_NONNULL((1));
void host_final_failure(HOST *host) G_GNUC_WGET_NONNULL((1));
void host_reset_failure(HOST *host) G_GNUC_WGET_NONNULL((1));

int queue_size(void) G_GNUC_WGET_PURE;
int queue_empty(void) G_GNUC_WGET_PURE;
void queue_print(HOST *host);

#endif /* _WGET_HOST_H */

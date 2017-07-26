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

struct JOB;
typedef struct JOB JOB;

// everything host/domain specific should go here
typedef struct {
	const char
		*scheme,
		*host;
	JOB
		*robot_job; // special job for downloading robots.txt (before anything else)
	ROBOTS
		*robots;
	wget_list_t
		*queue; // host specific job queue
	wget_hashmap_t
		*host_docs;
	long long
		retry_ts; // timestamp of earliest retry in milliseconds
	int
		qsize, // number of jobs in queue
		failures; // number of consequent connection failures
	uint16_t
		port;
	unsigned char
		blocked : 1; // host may be blocked after too many errors or even one final error
} HOST;

typedef struct {
	int
		http_status;
	wget_vector_t
		*docs;
} HOST_DOCS;

typedef struct {
	wget_iri_t
		*iri;
	long long
		size;
} DOC;

HOST *host_add(wget_iri_t *iri) G_GNUC_WGET_NONNULL((1));
HOST_DOCS *host_docs_add(wget_iri_t *iri, int status, long long size);
HOST *host_get(wget_iri_t *iri) G_GNUC_WGET_NONNULL((1));
HOST_DOCS *host_docs_get(wget_hashmap_t *host_docs, int status);
JOB *host_get_job(HOST *host, long long *pause);
JOB *host_add_job(HOST *host, JOB *job) G_GNUC_WGET_NONNULL((1,2));
JOB *host_add_robotstxt_job(HOST *host, wget_iri_t *iri, const char *encoding) G_GNUC_WGET_NONNULL((1,2));
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

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
 * host routines
 *
 * Changelog
 * 28.09.2013  Tim Ruehsen  created, moved from wget.c
 *
 * Each entry in hosts has it's own job queue. This allows to reuse
 * a connection for subsequent requests without expensive searching.
 */

#include <config.h>

#include <string.h>

#include <wget.h>

#include "wget_main.h"
#include "wget_host.h"
#include "wget_options.h"
#include "wget_job.h"
#include "wget_stats.h"

static wget_hashmap
	*hosts;
static wget_thread_mutex
	hosts_mutex;
static int
	qsize; // overall number of jobs

void host_init(void)
{
	wget_thread_mutex_init(&hosts_mutex);
}

void host_exit(void)
{
	wget_thread_mutex_destroy(&hosts_mutex);
}

static int _host_compare(const HOST *host1, const HOST *host2)
{
	int n;

	// If we use SCHEME here, we would eventually download robots.txt twice,
	//   e.g. for http://example.com and second for https://example.com.
	// This only makes sense when having the scheme and/or port within the directory name.

	if (host1->scheme != host2->scheme)
		return host1->scheme < host2->scheme ? -1 : 1;

	// host is already lowercase, no need to call strcasecmp()
	if ((n = wget_strcmp(host1->host, host2->host)))
		return n;

	return host1->port < host2->port ? -1 : (host1->port > host2->port ? 1 : 0);
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int _host_hash(const HOST *host)
{
	unsigned int hash = host->port; // use port as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	// We use SCHEME here, so we would eventually download robots.txt twice,
	//   e.g. for http://example.com and a second time for https://example.com.
	// Not unlikely that both are the same... but maybe they are not.

	hash = hash * 101 + host->scheme;

	for (p = (unsigned char *)host->host; p && *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static void _free_host_entry(HOST *host)
{
	if (host) {
		host_queue_free(host);
		wget_robots_free(&host->robots);
		wget_xfree(host);
	}
}

HOST *host_add(const wget_iri *iri)
{
	wget_thread_mutex_lock(hosts_mutex);

	if (!hosts) {
		hosts = wget_hashmap_create(16, (wget_hashmap_hash_fn *) _host_hash, (wget_hashmap_compare_fn *) _host_compare);
		wget_hashmap_set_key_destructor(hosts, (wget_hashmap_key_destructor *) _free_host_entry);
	}

	HOST *hostp = NULL, host = { .scheme = iri->scheme, .host = iri->host, .port = iri->port };

	if (!wget_hashmap_contains(hosts, &host)) {
		// info_printf("Add to hosts: %s\n", hostname);
		hostp = wget_memdup(&host, sizeof(host));
		wget_hashmap_put(hosts, hostp, hostp);
	}

	wget_thread_mutex_unlock(hosts_mutex);

	return hostp;
}

HOST *host_get(const wget_iri *iri)
{
	HOST *hostp, host = { .scheme = iri->scheme, .host = iri->host, .port = iri->port };

	wget_thread_mutex_lock(hosts_mutex);

	if (!hosts || !wget_hashmap_get(hosts, &host, &hostp))
		hostp = NULL;

	wget_thread_mutex_unlock(hosts_mutex);

	return hostp;
}

struct _find_free_job_context {
	JOB *job;
	long long now;
	long long pause;
};

static int _search_queue_for_free_job(struct _find_free_job_context *ctx, JOB *job)
{
	if (job->parts) {
		for (int it = 0; it < wget_vector_size(job->parts); it++) {
			PART *part = wget_vector_get(job->parts, it);

			if (!part->inuse) {
				part->inuse = 1;
				part->used_by = wget_thread_self();
				job->part = part;
				ctx->job = job;
				debug_printf("dequeue chunk %d/%d %s\n", it + 1, wget_vector_size(job->parts), job->metalink->name);
				return 1;
			}
		}
	} else if (!job->inuse) {
		// job may be paused due to a failure (retry later)
		long long pause = job->retry_ts - ctx->now;
		if (pause > 0) {
			if (!ctx->pause || ctx->pause < pause)
				ctx->pause = pause;
			return 0;
		}

		job->inuse = job->done = 1;
		job->used_by = wget_thread_self();
		job->part = NULL;
		ctx->job = job;
		debug_printf("dequeue job %s\n", job->iri->safe_uri);
		return 1;
	}

	return 0;
}

static int WGET_GCC_NONNULL((1,2)) _search_host_for_free_job(void *_ctx, const void *_host, WGET_GCC_UNUSED void *v)
{
	struct _find_free_job_context *ctx = _ctx;
	const HOST *host = _host;

	// host may be blocked due to max. number of failures reached
	if (host->blocked) {
		debug_printf("host %s is blocked (qsize=%d)\n", host->host, host->qsize);
		return 0;
	}

	// host may be pause due to a failure (retry later)
	long long pause = host->retry_ts - ctx->now;
	if (pause > 0) {
		debug_printf("host %s is paused %lldms\n", host->host, pause);
		if (!ctx->pause || ctx->pause < pause)
			ctx->pause = pause;
		return 0;
	}

	// do robots.txt job first before any other document
	if (host->robot_job) {
		if (!host->robot_job->inuse) {
			host->robot_job->inuse = host->robot_job->done = 1;
			host->robot_job->used_by = wget_thread_self();
			ctx->job = host->robot_job;
			debug_printf("host %s dequeue robot job\n", host->host);
			return 1;
		}

		debug_printf("robot job still in progress\n");
		return 0; // someone is still working on robots.txt
	}

	// find next job to do
	wget_list_browse(host->queue, (wget_list_browse_fn *) _search_queue_for_free_job, ctx);

	return ctx->job != 0; // 1=found a job, 0=no free job
}

/**
 * \param[in] host Host to get a job from or NULL for any host
 * \param[out] pause Time to wait before next act on host in milliseconds
 * \return Job detached from queue or NULL if there currently is no job
 *
 * Return the next job for a given host resp. for any host if \p host is NULL.
 *
 * If \p pause is given, it will be set to the number of milliseconds to wait
 * before the given host has a job offer. E.g. on connection errors we will wait
 * for a certain amount of time before we try again.
 */
JOB *host_get_job(HOST *host, long long *pause)
{
	struct _find_free_job_context ctx = { .now = wget_get_timemillis() };

	if (host) {
		_search_host_for_free_job(&ctx, host, NULL);
	} else {
		wget_thread_mutex_lock(hosts_mutex);
		wget_hashmap_browse(hosts, _search_host_for_free_job, &ctx);
		wget_thread_mutex_unlock(hosts_mutex);
	}

	if (pause)
		*pause = ctx.pause;

	return ctx.job;
}

static int _release_job(wget_thread_id *ctx, JOB *job)
{
	wget_thread_id self = *ctx;

	if (job->parts) {
		for (int it = 0; it < wget_vector_size(job->parts); it++) {
			PART *part = wget_vector_get(job->parts, it);

			if (!part->done && part->inuse && part->used_by == self) {
				part->inuse = 0;
				part->used_by = 0;
				debug_printf("released chunk %d/%d %s\n", it + 1, wget_vector_size(job->parts), job->blacklist_entry->local_filename);
			}
		}
	} else if (job->inuse && job->used_by == self) {
		job->inuse = job->done = 0;
		job->used_by = 0;
		debug_printf("released job %s\n", job->iri->safe_uri);
	}

	return 0;
}

void host_release_jobs(HOST *host)
{
	if (!host)
		return;

	wget_thread_id self = wget_thread_self();

	wget_thread_mutex_lock(hosts_mutex);

	if (host->robot_job) {
		if (host->robot_job->inuse && host->robot_job->used_by == self) {
			host->robot_job->inuse = host->robot_job->done = 0;
			host->robot_job->used_by = 0;
			debug_printf("released robots.txt job\n");
		}
	}

	wget_list_browse(host->queue, (wget_list_browse_fn *) _release_job, &self);

	wget_thread_mutex_unlock(hosts_mutex);
}

/**
 * \param host Host to append the job at
 * \param job Job to be appended at host's queue
 *
 * This function creates a shallow copy of \p job and appends
 * it to the host's job queue. This means for the caller that
 * he cares for free'ing \p job without free'ing any pointers within.
 */
void host_add_job(HOST *host, const JOB *job)
{
	JOB *jobp;

	if (job->blacklist_entry)
		debug_printf("%s: job fname %s\n", __func__, job->blacklist_entry->local_filename);

	wget_thread_mutex_lock(hosts_mutex);

	jobp = wget_list_append(&host->queue, job, sizeof(JOB));
	host->qsize++;
	if (!host->blocked)
		qsize++;

	jobp->host = host;

	if (jobp->iri) {
		debug_printf("%s: %p %s\n", __func__, (void *)jobp, jobp->iri->safe_uri);
	} else if (jobp->metalink)
		debug_printf("%s: %p %s\n", __func__, (void *)jobp, jobp->metalink->name);

	debug_printf("%s: qsize %d host-qsize=%d\n", __func__, qsize, host->qsize);

	wget_thread_mutex_unlock(hosts_mutex);
}

/**
 * \param[in] host Host to initialize the robots.txt job with
 * \param[in] iri IRI structure of robots.txt
 *
 * This function creates a priority job for robots.txt.
 * This job has to be processed before any other job.
 */
void host_add_robotstxt_job(HOST *host, const wget_iri *base, const char *encoding, bool http_fallback)
{
	JOB *job;
	blacklist_entry *blacklist_robots;
	wget_iri *robot_iri = wget_iri_parse_base(base, "/robots.txt", encoding);

	if (!robot_iri || !(blacklist_robots = blacklist_add(robot_iri))) {
		wget_iri_free(&robot_iri);
		return;
	}

	job = job_init(NULL, blacklist_robots, http_fallback);
	job->host = host;
	job->robotstxt = 1;

	wget_thread_mutex_lock(hosts_mutex);
	host->robot_job = job;
	host->qsize++;
	if (!host->blocked)
		qsize++;
	debug_printf("%s: %p %s\n", __func__, (void *)job, job->iri->safe_uri);
	debug_printf("%s: qsize %d host-qsize=%d\n", __func__, qsize, host->qsize);

	wget_thread_mutex_unlock(hosts_mutex);
}

static void _host_remove_job(HOST *host, JOB *job)
{
	debug_printf("%s: %p\n", __func__, (void *)job);

	if (job == host->robot_job) {
		// Special handling for automatic robots.txt jobs
		// ==============================================
		// What can happen with --recursive and --span-hosts is that a document from hostA
		// has links to hostB. All these links might go into the hostB queue before robots.txt
		// is downloaded and parsed. Right here we have downloaded and parsed robots.txt for hostB -
		// and only now we know if we should follow these links or not.
		// If any of these links that are disallowed have been explicitly requested by the user,
		// we still should download them. This holds true for sitemaps as well.
		if (host->robots) {
			JOB *next, *thejob = wget_list_getfirst(host->queue);

			for (int max = host->qsize - 1; max > 0; max--, thejob = next) {
				next = wget_list_getnext(thejob);

				if (thejob->requested_by_user)
						continue;

				if (thejob->sitemap)
						continue;

				for (int it = 0, n = wget_robots_get_path_count(host->robots); it < n; it++) {
					wget_string *path = wget_robots_get_path(host->robots, it);

					if (path->len && !strncmp(path->p + 1, thejob->iri->path ? thejob->iri->path : "", path->len - 1)) {
						info_printf(_("URL '%s' not followed (disallowed by robots.txt)\n"), thejob->iri->safe_uri);
						_host_remove_job(host, thejob);
						break;
					}
				}
			}
		}

		job_free(job);
		xfree(host->robot_job);
	} else {
		job_free(job);

		wget_list_remove(&host->queue, job);
	}

	host->qsize--;
	if (!host->blocked)
		qsize--;
}

/**
 * \param[in] host Host to remove the job from
 * \param[in] job Job to be removed
 *
 * Remove \p job from host's job queue.
 */
void host_remove_job(HOST *host, JOB *job)
{
	wget_thread_mutex_lock(hosts_mutex);
	_host_remove_job(host, job);
	debug_printf("%s: qsize=%d host->qsize=%d\n", __func__, qsize, host->qsize);
	wget_thread_mutex_unlock(hosts_mutex);
}

void hosts_free(void)
{
	// We don't need mutex locking here - this function is called on exit when all threads have ceased.
	wget_hashmap_free(&hosts);
}

void host_increase_failure(HOST *host)
{
	wget_thread_mutex_lock(hosts_mutex);
	host->failures++;
	host->retry_ts = wget_get_timemillis() + host->failures * 1000;
	debug_printf("%s: %s failures=%d\n", __func__, host->host, host->failures);

	if (config.tries && host->failures >= config.tries) {
		if (!host->blocked) {
			host->blocked = 1;
			qsize -= host->qsize;
			debug_printf("%s: qsize=%d\n", __func__, qsize);
		}
	}
	wget_thread_mutex_unlock(hosts_mutex);
}

void host_final_failure(HOST *host)
{
	wget_thread_mutex_lock(hosts_mutex);
	if (!host->blocked) {
		host->blocked = 1;
		qsize -= host->qsize;
		debug_printf("%s: qsize=%d\n", __func__, qsize);
	}
	wget_thread_mutex_unlock(hosts_mutex);
}

void host_reset_failure(HOST *host)
{
	wget_thread_mutex_lock(hosts_mutex);
	host->failures = 0;
	host->retry_ts = 0;
	if (host->blocked) {
		host->blocked = 0;
		qsize += host->qsize;
		debug_printf("%s: qsize=%d\n", __func__, qsize);
	}
	wget_thread_mutex_unlock(hosts_mutex);
}

/**
 * @return Whether the job queue is empty or not.
 */
int queue_empty(void)
{
	return !qsize;
}

// did I say, that I like nested function instead using contexts !?
// gcc, IBM and Intel support nested functions, just clang refuses it

static int _queue_free_func(void *context WGET_GCC_UNUSED, JOB *job)
{
	job_free(job);
	return 0;
}

void host_queue_free(HOST *host)
{
	wget_thread_mutex_lock(hosts_mutex);
	wget_list_browse(host->queue, (wget_list_browse_fn *) _queue_free_func, NULL);
	wget_list_free(&host->queue);
	if (host->robot_job) {
		job_free(host->robot_job);
		xfree(host->robot_job);
	}
	if (!host->blocked)
		qsize -= host->qsize;
	host->qsize = 0;
	wget_thread_mutex_unlock(hosts_mutex);
}

/*
static int _queue_print_func(void *context WGET_GCC_UNUSED, JOB *job)
{
	debug_printf("  %s %d\n", job->blacklist_entry->local_filename, job->inuse);
	return 0;
}

void queue_print(HOST *host)
{
	if (host->port)
		debug_printf("%s://%s:%hu\n", host->scheme, host->host, host->port);
	else
		debug_printf("%s://%s\n", host->scheme, host->host);

	wget_thread_mutex_lock(hosts_mutex);
	wget_list_browse(host->queue, (wget_list_browse_t)_queue_print_func, NULL);
	wget_thread_mutex_unlock(hosts_mutex);
}
*/

int queue_size(void)
{
	debug_printf("%s: qsize=%d\n", __func__, qsize);
	return qsize;
}

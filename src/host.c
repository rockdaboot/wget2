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
 * host routines
 *
 * Changelog
 * 28.09.2013  Tim Ruehsen  created, moved from wget.c
 *
 */

#include <config.h>

#include <string.h>

#include <wget.h>

#include "wget_main.h"
#include "wget_host.h"
#include "wget_options.h"
#include "wget_job.h"

static wget_hashmap_t
	*hosts;
static wget_thread_mutex_t
	hosts_mutex = WGET_THREAD_MUTEX_INITIALIZER;
static wget_thread_mutex_t
	host_docs_mutex = WGET_THREAD_MUTEX_INITIALIZER;
static int
	qsize; // overall number of jobs

struct site_stats{
	wget_buffer_t *buf;
	FILE *fp;
};

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
static int _host_docs_compare(const HOST_DOCS *host_docsp1, const HOST_DOCS *host_docsp2)
{
	if (host_docsp1->http_status != host_docsp2->http_status)
		return host_docsp1->http_status < host_docsp2->http_status ? -1 : 1;

	return 0;
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

	for (p = (unsigned char *)host->scheme; p && *p; p++)
		hash = hash * 101 + *p;

	for (p = (unsigned char *)host->host; p && *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static unsigned int _host_docs_hash(const HOST_DOCS *host_docsp)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter
	const unsigned char *p;
	char *buf;

	wget_asprintf(&buf, "%d", host_docsp->http_status);

	for (p = (const unsigned char *)buf; p && *p; p++)
		hash = hash * 101 + *p;

	xfree(buf);

	return hash;
}

static void _free_host_entry(HOST *host)
{
	if (host) {
		host_queue_free(host);
		wget_robots_free(&host->robots);
		wget_hashmap_free(&host->host_docs);
		wget_xfree(host);
	}
}

static void _free_host_docs_entry(HOST_DOCS *host_docsp)
{
	if (host_docsp) {
		wget_vector_free(&host_docsp->docs);
		wget_xfree(host_docsp);
	}
}

static void _free_docs_entry(DOC *doc)
{
	if (doc && doc->robot_iri)
		wget_iri_free(&(doc->iri));
}

HOST *host_add(wget_iri_t *iri)
{
	wget_thread_mutex_lock(&hosts_mutex);

	if (!hosts) {
		hosts = wget_hashmap_create(16, (wget_hashmap_hash_t)_host_hash, (wget_hashmap_compare_t)_host_compare);
		wget_hashmap_set_key_destructor(hosts, (wget_hashmap_key_destructor_t)_free_host_entry);
	}

	HOST *hostp = NULL, host = { .scheme = iri->scheme, .host = iri->host, .port = iri->port };

	if (!wget_hashmap_contains(hosts, &host)) {
		// info_printf("Add to hosts: %s\n", hostname);
		hostp = wget_memdup(&host, sizeof(host));
		wget_hashmap_put_noalloc(hosts, hostp, hostp);
	}

	wget_thread_mutex_unlock(&hosts_mutex);

	return hostp;
}

HOST_DOCS *host_docs_add(wget_iri_t *iri, wget_http_response_t *resp, bool robot_iri)
{
	HOST *hostp;
	wget_hashmap_t *host_docs;
	HOST_DOCS *host_docsp = NULL;
	wget_vector_t *docs;
	DOC *doc;

	wget_thread_mutex_lock(&host_docs_mutex);

	if ((hostp = host_get(iri))) {
		if (!(host_docs = hostp->host_docs)) {
			host_docs = wget_hashmap_create(16, (wget_hashmap_hash_t)_host_docs_hash, (wget_hashmap_compare_t)_host_docs_compare);
			wget_hashmap_set_key_destructor(host_docs, (wget_hashmap_key_destructor_t)_free_host_docs_entry);
			hostp->host_docs = host_docs;
		}

		if (!(host_docsp = host_docs_get(host_docs, resp->code))) {
			host_docsp = wget_malloc(sizeof(HOST_DOCS));
			host_docsp->http_status = resp->code;
			host_docsp->docs = NULL;
			wget_hashmap_put_noalloc(host_docs, host_docsp, host_docsp);
		}

		if (!(docs = host_docsp->docs)) {
			docs = wget_vector_create(8, -2, NULL);
			wget_vector_set_destructor(docs, (wget_vector_destructor_t)_free_docs_entry);
			host_docsp->docs = docs;
		}

		doc = wget_malloc(sizeof(DOC));
		doc->iri = iri;
		doc->size_downloaded = resp->cur_downloaded;
		doc->size_decompressed = resp->body->length;
		doc->encoding = resp->content_encoding;
		doc->robot_iri = robot_iri;
		wget_vector_add_noalloc(docs, doc);
	}

	wget_thread_mutex_unlock(&host_docs_mutex);

	return host_docsp;
}

HOST_DOCS *host_docs_get(wget_hashmap_t *host_docs, int status)
{
	HOST_DOCS *host_docsp = NULL, host_doc = {.http_status = status};

	if (host_docs)
		host_docsp = wget_hashmap_get(host_docs, &host_doc);

	return host_docsp;
}

HOST *host_get(wget_iri_t *iri)
{
	HOST *hostp, host = { .scheme = iri->scheme, .host = iri->host, .port = iri->port };

	wget_thread_mutex_lock(&hosts_mutex);

	if (hosts)
		hostp = wget_hashmap_get(hosts, &host);
	else
		hostp = NULL;

	wget_thread_mutex_unlock(&hosts_mutex);

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
		job->inuse = 1;
		job->used_by = wget_thread_self();
		job->part = NULL;
		ctx->job = job;
		debug_printf("dequeue job %s\n", job->iri->uri);
		return 1;
	}

	return 0;
}

static int G_GNUC_WGET_NONNULL_ALL _search_host_for_free_job(struct _find_free_job_context *ctx, HOST *host)
{
	debug_printf("qsize=%d blocked=%d\n", host->qsize, host->blocked);
	if (host->blocked)
		return 0;

	long long pause = host->retry_ts - ctx->now;
	debug_printf("pause=%lld\n", pause);
	if (pause > 0) {
		if (!ctx->pause || ctx->pause < pause)
			ctx->pause = pause;
		return 0;
	}

	if (host->robot_job) {
		if (!host->robot_job->inuse) {
			host->robot_job->inuse = 1;
			host->robot_job->used_by = wget_thread_self();
			ctx->job = host->robot_job;
			debug_printf("dequeue robot job %s\n", ctx->job->iri->uri);
			return 1;
		}
		debug_printf("robot job inuse\n");
		return 0; // someone is still working on robots.txt
	}

	wget_list_browse(host->queue, (wget_list_browse_t)_search_queue_for_free_job, ctx);

	return !!ctx->job;
}

JOB *host_get_job(HOST *host, long long *pause)
{
	struct _find_free_job_context ctx = { .now = wget_get_timemillis() };

	if (host) {
		_search_host_for_free_job(&ctx, host);
	} else {
		wget_thread_mutex_lock(&hosts_mutex);
		wget_hashmap_browse(hosts, (wget_hashmap_browse_t)_search_host_for_free_job, &ctx);
		wget_thread_mutex_unlock(&hosts_mutex);
	}

	if (pause)
		*pause = ctx.pause;

	return ctx.job;
}

static int _release_job(wget_thread_t *ctx, JOB *job)
{
	wget_thread_t self = *ctx;

	if (job->parts) {
		for (int it = 0; it < wget_vector_size(job->parts); it++) {
			PART *part = wget_vector_get(job->parts, it);

			if (part->inuse && part->used_by == self) {
				part->inuse = 0;
				part->used_by = 0;
				debug_printf("released chunk %d/%d %s\n", it + 1, wget_vector_size(job->parts), job->local_filename);
			}
		}
	} else if (job->inuse && job->used_by == self) {
		job->inuse = 0;
		job->used_by = 0;
		debug_printf("released job %s\n", job->iri->uri);
	}

	return 0;
}

void host_release_jobs(HOST *host)
{
	if (!host)
		return;

	wget_thread_t self = wget_thread_self();

	wget_thread_mutex_lock(&hosts_mutex);

	if (host->robot_job) {
		if (host->robot_job->inuse && host->robot_job->used_by == self) {
			host->robot_job->inuse = 0;
			host->robot_job->used_by = 0;
			debug_printf("released robots.txt job\n");
		}
	}

	wget_list_browse(host->queue, (wget_list_browse_t)_release_job, &self);

	wget_thread_mutex_unlock(&hosts_mutex);
}

JOB *host_add_job(HOST *host, JOB *job)
{
	JOB *jobp;

	job->host = host;
	debug_printf("%s: job fname %s\n", __func__, job->local_filename);

	wget_thread_mutex_lock(&hosts_mutex);
	jobp = wget_list_append(&host->queue, job, sizeof(JOB));
	host->qsize++;
	if (!host->blocked)
		qsize++;
	wget_thread_mutex_unlock(&hosts_mutex);

	if (job->iri)
		debug_printf("%s: %p %s\n", __func__, (void *)jobp, job->iri->uri);
	else if (job->metalink)
		debug_printf("%s: %p %s\n", __func__, (void *)jobp, job->metalink->name);

	debug_printf("%s: qsize %d host-qsize=%d\n", __func__, qsize, host->qsize);

	return jobp;
}

JOB *host_add_robotstxt_job(HOST *host, wget_iri_t *iri, const char *encoding)
{
	JOB *job;

	job = job_init(NULL, wget_iri_parse_base(iri, "/robots.txt", encoding));
	job->host = host;
	job->robotstxt = 1;
	job->local_filename = get_local_filename(job->iri);

	wget_thread_mutex_lock(&hosts_mutex);
	host->robot_job = job;
	host->qsize++;
	if (!host->blocked)
		qsize++;
	wget_thread_mutex_unlock(&hosts_mutex);

	debug_printf("%s: %p %s\n", __func__, (void *)job, job->iri->uri);
	debug_printf("%s: qsize %d host-qsize=%d\n", __func__, qsize, host->qsize);

	return job;
}

void host_remove_job(HOST *host, JOB *job)
{
	debug_printf("%s: %p\n", __func__, (void *)job);

	wget_thread_mutex_lock(&hosts_mutex);
	if (job == host->robot_job) {
		// Special handling for automatic robots.txt jobs
		// ==============================================
		// What can happen with --recursive and --span-hosts is that a document from hostA
		// has links to hostB. All these links might go into the hostB queue before robots.txt
		// is downloaded and parsed. Right here we have downloaded and parsed robots.txt for hostB -
		// and only now we know if we should follow these links or not.
		// If any of these links that are disallowed have been explicitly requested by the user,
		// we should download them.
		if (host->robots) {
			JOB *next, *thejob = wget_list_getfirst(host->queue);

			for (int max = host->qsize - 1; max > 0; max--, thejob = next) {
				next = wget_list_getnext(thejob);

				// info_printf("%s: checking '%s' / '%s'\n", __func__, thejob->iri->path, thejob->iri->uri);
				if (thejob->requested_by_user)
						continue;

				if (thejob->sitemap)
						continue;

				for (int it = 0; it < wget_vector_size(host->robots->paths); it++) {
					ROBOTS_PATH *path = wget_vector_get(host->robots->paths, it);

					// info_printf("%s: checked robot path '%.*s' / '%s' / '%s'\n", __func__, (int)path->len, path->path, thejob->iri->path, thejob->iri->uri);

					if (path->len && !strncmp(path->path + 1, thejob->iri->path ? thejob->iri->path : "", path->len - 1)) {
						info_printf(_("URL '%s' not followed (disallowed by robots.txt)\n"), thejob->iri->uri);
						host_remove_job(host, thejob);
						break;
					}
				}
			}
		}

		wget_iri_free(&job->iri);
		job_free(job);
		xfree(host->robot_job);
	} else {
		job_free(job);

		wget_list_remove(&host->queue, job);
	}

	host->qsize--;
	if (!host->blocked)
		qsize--;
	debug_printf("%s: qsize=%d host->qsize=%d\n", __func__, qsize, host->qsize);

	wget_thread_mutex_unlock(&hosts_mutex);
}

void hosts_free(void)
{
	// We don't need mutex locking here - this function is called on exit when all threads have ceased.
	wget_hashmap_free(&hosts);
}

void host_increase_failure(HOST *host)
{
	wget_thread_mutex_lock(&hosts_mutex);
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
	wget_thread_mutex_unlock(&hosts_mutex);
}

void host_final_failure(HOST *host)
{
	wget_thread_mutex_lock(&hosts_mutex);
	if (!host->blocked) {
		host->blocked = 1;
		qsize -= host->qsize;
		debug_printf("%s: qsize=%d\n", __func__, qsize);
	}
	wget_thread_mutex_unlock(&hosts_mutex);
}

void host_reset_failure(HOST *host)
{
	wget_thread_mutex_lock(&hosts_mutex);
	host->failures = 0;
	host->retry_ts = 0;
	if (host->blocked) {
		host->blocked = 0;
		qsize += host->qsize;
		debug_printf("%s: qsize=%d\n", __func__, qsize);
	}
	wget_thread_mutex_unlock(&hosts_mutex);
}

struct find_free_job_context {
	JOB **job;
	wget_http_connection_t *conn;
};

int queue_empty(void)
{
	return !qsize;
}

// did I say, that I like nested function instead using contexts !?
// gcc, IBM and Intel support nested functions, just clang refuses it

static int _queue_free_func(void *context G_GNUC_WGET_UNUSED, JOB *job)
{
	job_free(job);
	return 0;
}

void host_queue_free(HOST *host)
{
	wget_thread_mutex_lock(&hosts_mutex);
	wget_list_browse(host->queue, (wget_list_browse_t)_queue_free_func, NULL);
	wget_list_free(&host->queue);
	if (host->robot_job) {
		wget_iri_free(&host->robot_job->iri);
		job_free(host->robot_job);
		xfree(host->robot_job);
	}
	if (!host->blocked)
		qsize -= host->qsize;
	host->qsize = 0;
	wget_thread_mutex_unlock(&hosts_mutex);
}

static int _queue_print_func(void *context G_GNUC_WGET_UNUSED, JOB *job)
{
	info_printf("  %s %d\n", job->local_filename, job->inuse);
	return 0;
}

void queue_print(HOST *host)
{
	if (host->port)
		info_printf("%s://%s:%hu\n", host->scheme, host->host, host->port);
	else
		info_printf("%s://%s\n", host->scheme, host->host);

	wget_thread_mutex_lock(&hosts_mutex);
	wget_list_browse(host->queue, (wget_list_browse_t)_queue_print_func, NULL);
	wget_thread_mutex_unlock(&hosts_mutex);
}

int queue_size(void)
{
	debug_printf("%s: qsize=%d\n", __func__, qsize);
	return qsize;
}

static char *print_encoding(char encoding)
{
	switch (encoding) {
	case wget_content_encoding_identity:
		return "identity";
	case wget_content_encoding_gzip:
		return "gzip";
	case  wget_content_encoding_deflate:
		return "deflate";
	case wget_content_encoding_lzma:
		return "lzma";
	case wget_content_encoding_bzip2:
		return "bzip2";
	case wget_content_encoding_brotli:
		return "brotli";
	default:
		return "unknown encoding";
	}
}

static int host_docs_hashmap(struct site_stats *ctx, HOST_DOCS *host_docsp)
{
	char buf[16];

	wget_buffer_printf_append(ctx->buf, "  %8d  %13d\n", host_docsp->http_status, wget_vector_size(host_docsp->docs));

	for (int it = 0; it < wget_vector_size(host_docsp->docs); it++) {
		const DOC *doc = wget_vector_get(host_docsp->docs, it);
		wget_buffer_printf_append(ctx->buf, "         %s  %s (%s) : ",
				doc->iri->uri,
				wget_human_readable(buf, sizeof(buf),doc->size_downloaded),
				print_encoding(doc->encoding));
		wget_buffer_printf_append(ctx->buf, "%s (decompressed)\n",
				wget_human_readable(buf, sizeof(buf),doc->size_decompressed));
	}

	if (ctx->buf->length > 64*1024) {
		fprintf(ctx->fp, "%s", ctx->buf->data);
		wget_buffer_reset(ctx->buf);
	}

	return  0;
}

static int hosts_hashmap(struct site_stats *ctx, HOST *host)
{
	if (host->host_docs)
	{
		wget_buffer_printf_append(ctx->buf, "\n  %s:\n", host->host);
		wget_buffer_printf_append(ctx->buf, "  %8s  %13s\n", "Status", "No. of docs");

		wget_hashmap_browse(host->host_docs, (wget_hashmap_browse_t)host_docs_hashmap, ctx);
	}

	return 0;
}

void print_site_stats(wget_buffer_t *buf, FILE *fp)
{
	struct site_stats ctx = { .buf = buf, .fp = fp };
	wget_thread_mutex_lock(&hosts_mutex);

	wget_hashmap_browse(hosts, (wget_hashmap_browse_t)hosts_hashmap, &ctx);
	fprintf(fp, "%s", buf->data);

	wget_thread_mutex_unlock(&hosts_mutex);
}

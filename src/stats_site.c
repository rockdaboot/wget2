/*
 * Copyright(c) 2018-2019 Free Software Foundation, Inc.
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
 * Site statistics functions
 */
#include <config.h>

#include <wget.h>
#include <stdio.h>
#include <stdint.h>

#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"

enum {
	STATS_METHOD_GET = 1,
	STATS_METHOD_HEAD = 2,
	STATS_METHOD_POST = 3,
};

typedef struct {
	wget_iri_t
		*iri;
	long long
		size_downloaded,
		size_decompressed;
	long long
		request_start; // Milli timestamp initial request went out
	long long
		response_end; // Milli timestamp that final response read in
	long long
		initial_response_duration; // Number of millis between initial request, and first bytes back
	unsigned long long
		id, //!< unique id
		parent_id; //!< id of parent document (used for recursive mode)
	int
		status, //!< response status code
		signature_status; //!< 0=None 1=valid 2=invalid 3=bad 4=missing
	char
		encoding,
		method; //!< STATS_METHOD_*
	const char*
		mime_type;
	bool
		redirect : 1; //!< Was this a redirection ?
	time_t
		last_modified;
} site_stats_t;

// Forward declarations for static functions
static void print_human(stats_opts_t *opts, FILE *fp);
static void print_csv(stats_opts_t *opts, FILE *fp);
static void stats_callback(const void *stats);
static void free_stats(site_stats_t *stats);

static stats_print_func_t
	print_site[] = {
		[WGET_STATS_FORMAT_HUMAN] = print_human,
		[WGET_STATS_FORMAT_CSV] = print_csv,
	};

stats_opts_t stats_site_opts = {
	.tag = "Site",
	.options = &config.stats_site,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_site,
	.callback = stats_callback,
	.destructor = (wget_vector_destructor_t) free_stats,
	.print = print_site,
};

static wget_hashmap_t
	*docs;

void stats_site_add(wget_http_response_t *resp, wget_gpg_info_t *gpg_info)
{
	JOB *job = resp->req->user_data;
	wget_iri_t *iri = job->iri;

	if (gpg_info) {
		wget_thread_mutex_lock(stats_site_opts.mutex);

		if (!docs) {
			// lazy initialization, don't free keys or values when destructed.
			docs = wget_stringmap_create(128);
			wget_stringmap_set_key_destructor(docs, NULL);
			wget_stringmap_set_value_destructor(docs, NULL);

			// fill stringmap with existing stats data
			for (int it = 0; it < wget_vector_size(stats_site_opts.data); it++) {
				site_stats_t *e = wget_vector_get(stats_site_opts.data, it);

				wget_stringmap_put_noalloc(docs, e->iri->uri, e);
			}
		}

		// Find the original document and add result of verification.
		char *p, *uri = wget_strdup(iri->uri);

		if ((p = strrchr(uri, '.')))
			*p = 0;

		site_stats_t *doc;
		wget_stringmap_get(docs, uri, &doc);
		xfree(uri);

		if (doc) {
			if (gpg_info->valid_sigs)
				doc->signature_status = 1;
			else if (gpg_info->invalid_sigs)
				doc->signature_status = 2;
			else if (gpg_info->bad_sigs)
				doc->signature_status = 3;
			else if (gpg_info->missing_sigs)
				doc->signature_status = 4;

			wget_thread_mutex_unlock(stats_site_opts.mutex);
			return;
		}

		wget_thread_mutex_unlock(stats_site_opts.mutex);
	}

	site_stats_t *doc = wget_calloc(1, sizeof(site_stats_t));

	doc->id = job->id;
	doc->parent_id = job->parent_id;
	doc->iri = iri;
	doc->status = resp->code;
	doc->encoding = resp->content_encoding;
	doc->redirect = !!job->redirection_level;
	doc->mime_type = wget_strdup(resp->content_type);
	doc->last_modified = resp->last_modified;

	// Set the request start time (since this is the first request for the doc)
	// request_end will be overwritten by any subsequent responses for the doc.
	doc->request_start = resp->req->request_start;
	doc->response_end = resp->response_end;
	doc->initial_response_duration = resp->req->first_response_start - resp->req->request_start;

	doc->size_downloaded = resp->cur_downloaded;
	doc->size_decompressed = resp->body->length;

	if (!wget_strcasecmp_ascii(resp->req->method, "GET")) {
		doc->method = STATS_METHOD_GET;
	} else if (!wget_strcasecmp_ascii(resp->req->method, "HEAD")) {
		doc->size_downloaded = resp->content_length; // the would-be-length for GET requests
		doc->method = STATS_METHOD_HEAD;
	} else if (!wget_strcasecmp_ascii(resp->req->method, "POST")) {
		doc->method = STATS_METHOD_POST;
	}

	wget_thread_mutex_lock(stats_site_opts.mutex);
	wget_vector_add_noalloc(stats_site_opts.data, doc);
	if (docs)
		wget_stringmap_put_noalloc(docs, doc->iri->uri, doc);
	wget_thread_mutex_unlock(stats_site_opts.mutex);
}

static void stats_callback(G_GNUC_WGET_UNUSED const void *stats)
{
}

static void free_stats(site_stats_t *stats)
{
	if (stats) {
		xfree(stats->mime_type);
	}
}

static int print_human_entry(FILE *fp, site_stats_t *doc)
{
	long long transfer_time = doc->response_end - doc->request_start;

	fprintf(fp, "  %6d %5lld %6lld %s\n",
		doc->status, transfer_time, doc->size_downloaded, doc->iri->uri);

	return 0;
}

static int print_csv_entry(FILE *fp, site_stats_t *doc)
{
	long long transfer_time = doc->response_end - doc->request_start;

	fprintf(fp, "%llu,%llu,%s,%d,%d,%d,%lld,%lld,%lld,%lld,%d,%d,%ld,%s\n",
		doc->id, doc->parent_id, doc->iri->uri, doc->status, !doc->redirect, doc->method,
		doc->size_downloaded, doc->size_decompressed, transfer_time,
		doc->initial_response_duration, doc->encoding, doc->signature_status, doc->last_modified, doc->mime_type);

	return 0;
}

static void print_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nSite Statistics:\n");
	fprintf(fp, "  %6s %5s %6s %s\n", "Status", "ms", "Size", "URL");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_human_entry, fp);

	if (config.debug)
		wget_stringmap_free(&docs);
}

static void print_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "ID,ParentID,URL,Status,Link,Method,Size,SizeDecompressed,TransferTime,ResponseTime,Encoding,Verification,Last-Modified,Content-Type\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_csv_entry, fp);

	if (config.debug)
		wget_stringmap_free(&docs);
}

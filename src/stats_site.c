/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdint.h>

#include <wget.h>
#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"

enum {
	STATS_METHOD_GET = 1,
	STATS_METHOD_HEAD = 2,
	STATS_METHOD_POST = 3,
};

typedef struct {
	const wget_iri
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
	int64_t
		last_modified;
} site_stats_data;

static wget_vector
	*data;

static wget_thread_mutex
	mutex;

static wget_hashmap
	*docs;

static FILE
	*fp;

static void free_stats(void *stats)
{
	site_stats_data *s = stats;

	if (s) {
		xfree(s->mime_type);
		xfree(s);
	}
}

void site_stats_init(FILE *fpout)
{
	wget_thread_mutex_init(&mutex);

	data = wget_vector_create(8, NULL);
	wget_vector_set_destructor(data, free_stats);

	fp = fpout;
}

void site_stats_exit(void)
{
	wget_stringmap_free(&docs);

	wget_vector_free(&data);
	wget_thread_mutex_destroy(&mutex);
}

void stats_site_add(wget_http_response *resp, wget_gpg_info_t *gpg_info)
{
	JOB *job = resp->req->user_data;
	const wget_iri *iri = job->iri;

	if (gpg_info) {
		wget_thread_mutex_lock(mutex);

		if (!docs) {
			// lazy initialization, don't free keys or values when destructed.
			docs = wget_stringmap_create(128);
			wget_stringmap_set_key_destructor(docs, NULL);
			wget_stringmap_set_value_destructor(docs, NULL);

			// fill stringmap with existing stats data
			for (int it = 0; it < wget_vector_size(data); it++) {
				site_stats_data *e = wget_vector_get(data, it);

				wget_stringmap_put(docs, e->iri->uri, e);
			}
		}

		// Find the original document and add result of verification.
		char *p, *uri = wget_strdup(iri->uri);

		if ((p = strrchr(uri, '.')))
			*p = 0;

		site_stats_data *doc;
		int rc = wget_stringmap_get(docs, uri, &doc);
		xfree(uri);

		if (rc && doc) {
			if (gpg_info->valid_sigs)
				doc->signature_status = 1;
			else if (gpg_info->invalid_sigs)
				doc->signature_status = 2;
			else if (gpg_info->bad_sigs)
				doc->signature_status = 3;
			else if (gpg_info->missing_sigs)
				doc->signature_status = 4;

			wget_thread_mutex_unlock(mutex);
			return;
		}

		wget_thread_mutex_unlock(mutex);
	}

	site_stats_data *doc = wget_calloc(1, sizeof(site_stats_data));

	doc->id = job->id;
	doc->parent_id = job->parent_id;
	doc->iri = iri;
	doc->status = resp->code;
	doc->encoding = resp->content_encoding;
	doc->redirect = job->redirection_level != 0;
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

	wget_thread_mutex_lock(mutex);
	wget_vector_add(data, doc);
	if (docs)
		wget_stringmap_put(docs, doc->iri->uri, doc);
	wget_thread_mutex_unlock(mutex);
}

static int print_human_entry(FILE *_fp, site_stats_data *doc)
{
	long long transfer_time = doc->response_end - doc->request_start;
	wget_fprintf(_fp, "  %6d %5lld %6lld %s\n",
		doc->status, transfer_time, doc->size_downloaded, doc->iri->safe_uri);

	return 0;
}

static int print_csv_entry(FILE *_fp, site_stats_data *doc)
{
	long long transfer_time = doc->response_end - doc->request_start;
	wget_fprintf(_fp, "%llu,%llu,%s,%d,%d,%d,%lld,%lld,%lld,%lld,%d,%d,%lld,%s\n",
		doc->id, doc->parent_id, doc->iri->uri, doc->status, !doc->redirect, doc->method,
		doc->size_downloaded, doc->size_decompressed, transfer_time,
		doc->initial_response_duration, doc->encoding, doc->signature_status,
		(long long) doc->last_modified, doc->mime_type);

	return 0;
}

static void print_human(void)
{
	wget_fprintf(fp, "\nSite Statistics:\n");
	wget_fprintf(fp, "  %6s %5s %6s %s\n", "Status", "ms", "Size", "URL");
	wget_vector_browse(data, (wget_vector_browse_fn *) print_human_entry, fp);
}

static void print_csv(void)
{
	wget_fprintf(fp, "ID,ParentID,URL,Status,Link,Method,Size,SizeDecompressed,TransferTime,ResponseTime,Encoding,Verification,Last-Modified,Content-Type\n");
	wget_vector_browse(data, (wget_vector_browse_fn *) print_csv_entry, fp);
}

void site_stats_print(void)
{
	if (config.stats_site_args->format == WGET_STATS_FORMAT_HUMAN)
		print_human();
	else
		print_csv();
}

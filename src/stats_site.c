/*
 * Copyright(c) 2018 Free Software Foundation, Inc.
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
	STATS_SCHEME_GET = 1,
	STATS_SCHEME_HEAD = 2,
	STATS_SCHEME_POST = 3,
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
		valid_sigs, //!< Number of valid GPG signatures inside the doc. Meaningless if !is_sig.
		invalid_sigs, //!< Number of invalid GPG signatures inside the dov. Meaningless if !is_sig.
		missing_sigs, //!< Number of GPG signatures with missing public keys. Meaningless if !is_sig.
		bad_sigs; //!< Number of bad GPG signatures. Meaningless if !is_sig.
	char
		encoding,
		scheme; //!< STATS_SCHEME_*
	bool
		is_sig : 1, //!< Is this DOC a signature for a file ?
		redirect : 1; //!< Was this a redirection ?
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

void stats_site_add(wget_http_response_t *resp, wget_gpg_info_t *gpg_info)
{
	JOB *job = resp->req->user_data;
	wget_iri_t *iri = job->iri;

	site_stats_t *doc = wget_calloc(1, sizeof(site_stats_t));

	doc->id = job->id;
	doc->parent_id = job->parent_id;
	doc->iri = iri;
	doc->status = resp->code;
	doc->encoding = resp->content_encoding;
	doc->redirect = !!job->redirection_level;

	// Set the request start time (since this is the first request for the doc)
	// request_end will be overwritten by any subsequent responses for the doc.
	doc->request_start = resp->req->request_start;
	doc->response_end = resp->response_end;
	doc->initial_response_duration = resp->req->first_response_start - resp->req->request_start;

	doc->size_downloaded = resp->cur_downloaded;
	doc->size_decompressed = resp->body->length;

	if (!wget_strcasecmp_ascii(resp->req->method, "GET")) {
		doc->scheme = STATS_SCHEME_GET;
	} else if (!wget_strcasecmp_ascii(resp->req->method, "HEAD")) {
		doc->size_downloaded = resp->content_length; // the would-be-length for GET requests
		doc->scheme = STATS_SCHEME_HEAD;
	} else if (!wget_strcasecmp_ascii(resp->req->method, "POST")) {
		doc->scheme = STATS_SCHEME_POST;
	}

	if (gpg_info) {
		doc->is_sig = 1;
		doc->valid_sigs = gpg_info->valid_sigs;
		doc->invalid_sigs = gpg_info->invalid_sigs;
		doc->missing_sigs = gpg_info->missing_sigs;
		doc->bad_sigs = gpg_info->bad_sigs;
	}

	wget_thread_mutex_lock(stats_site_opts.mutex);
	wget_vector_add_noalloc(stats_site_opts.data, doc);
	wget_thread_mutex_unlock(stats_site_opts.mutex);
}

static void stats_callback(G_GNUC_WGET_UNUSED const void *stats)
{
}

static void free_stats(G_GNUC_WGET_UNUSED site_stats_t *stats)
{
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

	fprintf(fp, "%llu,%llu,%s,%d,%d,%d,%lld,%lld,%lld,%lld,%d,%d,%d,%d,%d,%d\n",
		doc->id, doc->parent_id, doc->iri->uri, doc->status, !doc->redirect, doc->scheme,
		doc->size_downloaded, doc->size_decompressed, transfer_time,
		doc->initial_response_duration, doc->encoding,
		doc->is_sig, doc->valid_sigs,
		doc->invalid_sigs, doc->missing_sigs, doc->bad_sigs);

	return 0;
}

static void print_human(G_GNUC_WGET_UNUSED stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nSite Statistics:\n");
	fprintf(fp, "  %6s %5s %6s %s\n", "Status", "ms", "Size", "Host");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_human_entry, fp);
}

static void print_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "ID,ParentID,URL,Status,Link,Protocol,Size,SizeDecompressed,TransferTime,ResponseTime,Encoding,IsSig,Valid,Invalid,Missing,Bad\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_csv_entry, fp);
}

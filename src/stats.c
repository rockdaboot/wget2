/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
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
 * Statistics
 *
 */
#include <config.h>
#include <wget.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <glob.h>

#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"
#include "wget_host.h"
#include "wget_utils.h"

// Forward declarations for static functions

static wget_thread_mutex_t
	host_docs_mutex,
	tree_docs_mutex,
	hosts_mutex;

static void stats_print_ocsp_human(stats_opts_t *opts, FILE *fp);
static void stats_print_ocsp_csv(stats_opts_t *opts, FILE *fp);
static void stats_print_ocsp_json(stats_opts_t *opts, FILE *fp);
static void stats_print_server_human(stats_opts_t *opts, FILE *fp);
static void stats_print_server_csv(stats_opts_t *opts, FILE *fp);
static void stats_print_server_json(stats_opts_t *opts, FILE *fp);
static void stats_print_site_human(stats_opts_t *opts, FILE *fp);
static void stats_print_site_csv(stats_opts_t *opts, FILE *fp);
static void stats_print_site_json(stats_opts_t *opts, FILE *fp);
static void stats_print_site_tree(stats_opts_t *opts, FILE *fp);
static void stats_print_tls_human(stats_opts_t *opts, FILE *fp);
static void stats_print_tls_csv(stats_opts_t *opts, FILE *fp);
static void stats_print_tls_json(stats_opts_t *opts, FILE *fp);

extern stats_print_func_t
	print_dns[];
/*
static stats_print_func_t
	print_dns[] = {
		[WGET_STATS_FORMAT_HUMAN] = stats_print_dns_human,
		[WGET_STATS_FORMAT_CSV] = stats_print_dns_csv,
		[WGET_STATS_FORMAT_JSON] = stats_print_dns_json,
	};
*/
static stats_print_func_t
	print_ocsp[] = {
		[WGET_STATS_FORMAT_HUMAN] = stats_print_ocsp_human,
		[WGET_STATS_FORMAT_CSV] = stats_print_ocsp_csv,
		[WGET_STATS_FORMAT_JSON] = stats_print_ocsp_json,
	};
static stats_print_func_t
	print_server[] = {
		[WGET_STATS_FORMAT_HUMAN] = stats_print_server_human,
		[WGET_STATS_FORMAT_CSV] = stats_print_server_csv,
		[WGET_STATS_FORMAT_JSON] = stats_print_server_json,
	};
static stats_print_func_t
	print_site[] = {
		[WGET_STATS_FORMAT_HUMAN] = stats_print_site_human,
		[WGET_STATS_FORMAT_CSV] = stats_print_site_csv,
		[WGET_STATS_FORMAT_JSON] = stats_print_site_json,
		[WGET_STATS_FORMAT_TREE] = stats_print_site_tree,
	};
static stats_print_func_t
	print_tls[] = {
		[WGET_STATS_FORMAT_HUMAN] = stats_print_tls_human,
		[WGET_STATS_FORMAT_CSV] = stats_print_tls_csv,
		[WGET_STATS_FORMAT_JSON] = stats_print_tls_json,
	};

extern stats_opts_t stats_dns_opts;

static stats_opts_t stats_ocsp_opts = {
	.tag = "OCSP",
	.options = &config.stats_ocsp,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_ocsp,
	.callback = stats_callback_ocsp,
	.destructor = (wget_vector_destructor_t) free_ocsp_stats,
	.print = print_ocsp,
};
static stats_opts_t stats_server_opts = {
	.tag = "Server",
	.options = &config.stats_server,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_server,
	.callback = stats_callback_server,
	.destructor = (wget_vector_destructor_t) free_server_stats,
	.print = print_server,
};
static stats_opts_t stats_site_opts = {
	.tag = "Site",
	.options = &config.stats_site,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_site,
	.callback = stats_callback_site,
	.destructor = (wget_vector_destructor_t) free_site_stats,
	.print = print_site,
};
static stats_opts_t stats_tls_opts = {
	.tag = "TLS",
	.options = &config.stats_tls,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_tls,
	.callback = stats_callback_tls,
	.destructor = (wget_vector_destructor_t) free_tls_stats,
	.print = print_tls,
};

static stats_opts_t *stats_opts[] = {
	[WGET_STATS_TYPE_DNS] = &stats_dns_opts,
	[WGET_STATS_TYPE_OCSP] = &stats_ocsp_opts,
	[WGET_STATS_TYPE_SERVER] = &stats_server_opts,
	[WGET_STATS_TYPE_SITE] = &stats_site_opts,
	[WGET_STATS_TYPE_TLS] = &stats_tls_opts,
};

static wget_hashmap_t
	*hosts;

static char tabs[] = "\t\t\t\t\t\t\t\t\t\t";

void stats_set_hosts(wget_hashmap_t *_hosts, wget_thread_mutex_t _hosts_mutex)
{
	hosts = _hosts;
	hosts_mutex = _hosts_mutex;
}

static HOST *stats_host_get(wget_iri_t *iri)
{
	if (!hosts)
		return NULL;

	HOST *hostp, host = { .scheme = iri->scheme, .host = iri->host, .port = iri->port };

	wget_thread_mutex_lock(hosts_mutex);
	hostp = wget_hashmap_get(hosts, &host);
	wget_thread_mutex_unlock(hosts_mutex);

	return hostp;
}

static int _host_docs_compare(const HOST_DOCS *host_docsp1, const HOST_DOCS *host_docsp2)
{
	if (host_docsp1->http_status != host_docsp2->http_status)
		return host_docsp1->http_status < host_docsp2->http_status ? -1 : 1;

	return 0;
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int _host_docs_hash(const HOST_DOCS *host_docsp)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	for (unsigned x = host_docsp->http_status; x; x /= 16)
		hash = hash * 101 + (x & 0xF);

	return hash;
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int _stats_iri_hash(wget_iri_t *iri)
{
	unsigned int h = iri->port; // use port as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	for (p = (unsigned char *)iri->scheme; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->host; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->path; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->query; p && *p; p++)
		h = h * 101 + *p;

	return h;
}

static int _stats_iri_compare(wget_iri_t *iri1, wget_iri_t *iri2)
{
	return wget_iri_compare(iri1, iri2);
}

static void *stats_docs_get(wget_hashmap_t *h, wget_iri_t *iri)
{
	if (h)
		return wget_hashmap_get(h, iri);

	return NULL;
}

static void _free_host_docs_entry(HOST_DOCS *host_docsp)
{
	if (host_docsp) {
		wget_hashmap_free(&host_docsp->docs);
		wget_xfree(host_docsp);
	}
}

static void _free_tree_docs_entry(TREE_DOCS *tree_docsp)
{
	if (tree_docsp) {
		wget_vector_clear_nofree(tree_docsp->children);
		wget_vector_free(&tree_docsp->children);
		wget_xfree(tree_docsp);
	}
}

static HOST_DOCS *host_docs_get(wget_hashmap_t *host_docs, int status)
{
	HOST_DOCS *host_docsp = NULL, host_doc = {.http_status = status};

	if (host_docs)
		host_docsp = wget_hashmap_get(host_docs, &host_doc);

	return host_docsp;
}

DOC *stats_docs_add(wget_iri_t *iri, wget_http_response_t *resp)
{
	wget_hashmap_t *host_docs, *docs;
	HOST_DOCS *host_docsp;
	DOC *doc;
	HOST *hostp;

	if (!(hostp = stats_host_get(iri))) {
		error_printf(_("No existing host entry for %s\n"), iri->uri);
		return NULL;
	}

	wget_thread_mutex_lock(host_docs_mutex);

	if (!(host_docs = hostp->host_docs)) {
		host_docs = wget_hashmap_create(16, (wget_hashmap_hash_t)_host_docs_hash, (wget_hashmap_compare_t)_host_docs_compare);
		wget_hashmap_set_key_destructor(host_docs, (wget_hashmap_key_destructor_t)_free_host_docs_entry);
		hostp->host_docs = host_docs;
	}

	if (!(host_docsp = host_docs_get(host_docs, resp->code))) {
		host_docsp = wget_calloc(1, sizeof(HOST_DOCS));
		host_docsp->http_status = resp->code;
		host_docsp->docs = NULL;
		wget_hashmap_put_noalloc(host_docs, host_docsp, host_docsp);
	}

	if (!(docs = host_docsp->docs)) {
		docs = wget_hashmap_create(16, (wget_hashmap_hash_t)_stats_iri_hash, (wget_hashmap_compare_t)_stats_iri_compare);
		wget_hashmap_set_key_destructor(docs, (wget_hashmap_key_destructor_t)NULL);
		host_docsp->docs = docs;
	}

	if (!(doc = stats_docs_get(docs, iri))) {
		doc = wget_calloc(1, sizeof(DOC));
		doc->iri = iri;
		doc->status = resp->code;
		doc->encoding = resp->content_encoding;

		// Set the request start time (since this is the first request for the doc)
		// request_end will be overwritten by any subsequent responses for the doc.
		doc->request_start = resp->req->request_start;
		doc->response_end = resp->response_end;
		doc->initial_response_duration = resp->req->first_response_start - resp->req->request_start;
		doc->is_sig = 0; // We are unsure if the DOC is a signature or not.

		if (!wget_strcasecmp_ascii(resp->req->method, "HEAD"))
			doc->head_req = true;
		wget_hashmap_put_noalloc(docs, doc->iri, doc);

	} else {
		// The final response right now.
		doc->response_end = resp->response_end;
	}

	if (resp->code == 206) { // --chunk-size
		doc->size_downloaded += resp->cur_downloaded;
		doc->size_decompressed += resp->body->length;
	} else { // second GET after first HEAD for --spider
		doc->size_downloaded = resp->cur_downloaded;
		doc->size_decompressed = resp->body->length;
	}

	wget_thread_mutex_unlock(host_docs_mutex);

	return doc;
}

TREE_DOCS *stats_tree_docs_add(wget_iri_t *parent_iri, wget_iri_t *iri, wget_http_response_t *resp, bool robot_iri, bool redirect, DOC *doc)
{
	HOST *hostp = NULL;
	wget_hashmap_t *tree_docs;
	TREE_DOCS *parent_node, *child_node = NULL;
	wget_vector_t *children = NULL;

	if (!doc)
		return NULL;

	if (parent_iri && !(hostp = stats_host_get(parent_iri))) {
		error_printf(_("No existing host entry for parent %s\n"), parent_iri->uri);
		return NULL;
	}

	wget_thread_mutex_lock(tree_docs_mutex);

	if (parent_iri) {
		if (!(parent_node = stats_docs_get(hostp->tree_docs, parent_iri))) {
			error_printf(_("No existing entry for %s in tree_docs hashmap\n"), parent_iri->uri);
			goto out;
		}

		if (!(children = parent_node->children))
			children = parent_node->children = wget_vector_create(8, -2, NULL);
	}

	if (!(hostp = stats_host_get(iri))) {
		error_printf(_("No existing host entry for %s\n"), iri->uri);
		goto out;
	}

	if (!(tree_docs = hostp->tree_docs)) {
		hostp->tree_docs = tree_docs = wget_hashmap_create(16, (wget_hashmap_hash_t)_stats_iri_hash, (wget_hashmap_compare_t)_stats_iri_compare);
		wget_hashmap_set_key_destructor(tree_docs, (wget_hashmap_key_destructor_t)NULL);
		wget_hashmap_set_value_destructor(tree_docs, (wget_hashmap_value_destructor_t)_free_tree_docs_entry);
	}

	if (!(child_node = stats_docs_get(tree_docs, iri))) {
		child_node = wget_calloc(1, sizeof(TREE_DOCS));
		child_node->iri = iri;
		child_node->doc = doc;
		child_node->children = NULL;
		child_node->redirect = redirect;
		wget_hashmap_put_noalloc(tree_docs, child_node->iri, child_node);
	} else {
		if (child_node->doc->head_req && wget_strcasecmp_ascii(resp->req->method, "HEAD")) {
			child_node->doc = doc;
			child_node->redirect = redirect;
		} else {
			// error_printf(_("Existing entry for %s in tree_docs hashmap of host %s://%s\n"), iri->uri, hostp->scheme, hostp->host);
			goto out;
		}
	}

	if (parent_iri)
		wget_vector_add_noalloc(children, child_node);
	else {
		if (robot_iri)
			hostp->robot = child_node;
		else
			hostp->root = child_node;
	}

	if (hostp->robot && (wget_hashmap_size(hostp->tree_docs) == 2)) {
		if (!child_node->children)
			child_node->children = wget_vector_create(8, -2, NULL);
		wget_vector_add_noalloc(child_node->children, hostp->robot);
	}

out:
	wget_thread_mutex_unlock(tree_docs_mutex);

	return child_node;
}

void stats_callback_tls(const void *stats)
{
	tls_stats_t tls_stats = { .false_start = -1, .tfo = -1, .tls_con = -1, .resumed = -1, .tcp_protocol = -1, .cert_chain_size = -1, .millisecs = -1 };

	tls_stats.hostname = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_HOSTNAME, stats));
	tls_stats.version = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats));
	tls_stats.alpn_proto = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_ALPN_PROTO, stats));

	tls_stats.hostname = NULL_TO_DASH(tls_stats.hostname);
	tls_stats.version = NULL_TO_DASH(tls_stats.version);
	tls_stats.alpn_proto = NULL_TO_DASH(tls_stats.alpn_proto);

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats))
		tls_stats.false_start = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats))
		tls_stats.tfo = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats))
		tls_stats.tls_con = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats))
		tls_stats.resumed = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_TCP_PROTO, stats))
		tls_stats.tcp_protocol = *((char *)wget_tcp_get_stats_tls(WGET_STATS_TLS_TCP_PROTO, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats))
		tls_stats.cert_chain_size = *((int *)wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats));

	if (wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats))
		tls_stats.millisecs = *((long long *)wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats));

	wget_thread_mutex_lock(stats_tls_opts.mutex);
	wget_vector_add(stats_tls_opts.data, &tls_stats, sizeof(tls_stats_t));
	wget_thread_mutex_unlock(stats_tls_opts.mutex);
}

void stats_callback_server(const void *stats)
{
	server_stats_t server_stats = { .hpkp_new = -1, .hsts = -1, .csp = -1, .hpkp = WGET_STATS_HPKP_NO };

	server_stats.hostname = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HOSTNAME, stats));
	server_stats.ip = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_IP, stats));
	server_stats.scheme = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_SCHEME, stats));

	server_stats.hostname = NULL_TO_DASH(server_stats.hostname);
	server_stats.ip = NULL_TO_DASH(server_stats.ip);
	server_stats.scheme = NULL_TO_DASH(server_stats.scheme);

	if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP_NEW, stats))
		server_stats.hpkp_new = *((char *)wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP_NEW, stats));

	if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HSTS, stats))
		server_stats.hsts = *((char *)wget_tcp_get_stats_server(WGET_STATS_SERVER_HSTS, stats));

	if (wget_tcp_get_stats_server(WGET_STATS_SERVER_CSP, stats))
		server_stats.csp = *((char *)wget_tcp_get_stats_server(WGET_STATS_SERVER_CSP, stats));

	if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats))
		server_stats.hpkp = *((char *)wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats));

	wget_thread_mutex_lock(stats_server_opts.mutex);
	wget_vector_add(stats_server_opts.data, &server_stats, sizeof(server_stats_t));
	wget_thread_mutex_unlock(stats_server_opts.mutex);
}

void stats_callback_ocsp(const void *stats)
{
	ocsp_stats_t ocsp_stats = { .nvalid = -1, .nrevoked = -1, .nignored = -1 };

	ocsp_stats.hostname = wget_strdup(wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_HOSTNAME, stats));
	ocsp_stats.hostname = NULL_TO_DASH(ocsp_stats.hostname);

	if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats))
		ocsp_stats.nvalid = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats));

	if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats))
		ocsp_stats.nrevoked = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats));

	if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats))
		ocsp_stats.nignored = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats));

	wget_thread_mutex_lock(stats_ocsp_opts.mutex);
	wget_vector_add(stats_ocsp_opts.data, &ocsp_stats, sizeof(ocsp_stats_t));
	wget_thread_mutex_unlock(stats_ocsp_opts.mutex);
}

void stats_callback_site(const void *stats)
{
}

void free_tls_stats(tls_stats_t *stats)
{
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->version);
		xfree(stats->alpn_proto);
	}
}

void free_server_stats(server_stats_t *stats)
{
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->ip);
		xfree(stats->scheme);
	}
}

void free_site_stats(site_stats_t *stats)
{
}

void free_ocsp_stats(ocsp_stats_t *stats)
{
	if (stats)
		xfree(stats->hostname);
}

static int stats_parse_options(const char *val, wget_stats_format_t *format, const char **filename)
{
	const char *p = val;

	if ((p = strchr(val, ':'))) {
		if (!wget_strncasecmp_ascii("human", val, p - val) || !wget_strncasecmp_ascii("h", val, p - val))
			*format = WGET_STATS_FORMAT_HUMAN;
		else if (!wget_strncasecmp_ascii("csv", val, p - val))
			*format = WGET_STATS_FORMAT_CSV;
		else if (!wget_strncasecmp_ascii("json", val, p - val))
			*format = WGET_STATS_FORMAT_JSON;
		else if (!wget_strncasecmp_ascii("tree", val, p - val))
			*format = WGET_STATS_FORMAT_TREE;
		else {
			error_printf(_("Unknown stats format '%s'\n"), val);
			return -1;
		}

		val = p + 1;
	} else // no format given
		*format = WGET_STATS_FORMAT_HUMAN;

	*filename = shell_expand(val);

	return 0;
}

int stats_init(void)
{
//	for (stats_opts_t *opts = stats_opts; opts < stats_opts + countof(stats_opts); opts++) {
	for (unsigned it = 0; it < countof(stats_opts); it++) {
		stats_opts_t *opts = stats_opts[it];

		if (!*opts->options)
			continue;

		if (stats_parse_options(*opts->options, &opts->format, &opts->file))
			return -1;

		if (!opts->print[opts->format]) {
			error_printf(_("Stats format not supported by %s stats \n"), opts->tag);
			return -1;
		}

		wget_thread_mutex_init(&opts->mutex);

		opts->data = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(opts->data, opts->destructor);
		opts->set_callback(opts->callback);
	}

	wget_thread_mutex_init(&host_docs_mutex);
	wget_thread_mutex_init(&tree_docs_mutex);

	return 0;
}

void stats_exit(void)
{
	for (unsigned it = 0; it < countof(stats_opts); it++) {
		wget_vector_free(&stats_opts[it]->data);
		wget_thread_mutex_destroy(&stats_opts[it]->mutex);
		xfree(stats_opts[it]->file);
	}

	wget_thread_mutex_destroy(&host_docs_mutex);
	wget_thread_mutex_destroy(&tree_docs_mutex);
}

static const char *print_encoding(char encoding)
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

static int _docs_hashmap(struct site_stats *ctx, G_GNUC_WGET_UNUSED wget_iri_t *iri, DOC *doc)
{
	fprintf(ctx->fp, "         %s  %lld bytes (%s) : ",
		doc->iri->uri,
		doc->size_downloaded,
		print_encoding(doc->encoding));

	fprintf(ctx->fp, "%lld bytes (decompressed), %lldms (transfer) : %lldms (response)\n",
		doc->size_decompressed,
		doc->response_end - doc->request_start,
		doc->initial_response_duration);

	if (doc->is_sig) {
		fprintf(ctx->fp, "           Signatures: %d (valid), %d (invalid), %d (missing), %d (bad)\n",
			doc->valid_sigs,
			doc->invalid_sigs,
			doc->missing_sigs,
			doc->bad_sigs);
	}

	return 0;
}

static int host_docs_hashmap(struct site_stats *ctx, HOST_DOCS *host_docsp)
{
	if (host_docsp) {
		fprintf(ctx->fp, "  %8d  %13d\n", host_docsp->http_status, wget_hashmap_size(host_docsp->docs));
		wget_hashmap_browse(host_docsp->docs, (wget_hashmap_browse_t) _docs_hashmap, ctx);
	}

	return  0;
}

static int hosts_hashmap(struct site_stats *ctx, HOST *host)
{
	if (host->host_docs) {
		fprintf(ctx->fp, "\n  %s://%s:\n", host->scheme, host->host);
		fprintf(ctx->fp, "  %8s  %13s\n", "Status", "No. of docs");

		wget_hashmap_browse(host->host_docs, (wget_hashmap_browse_t) host_docs_hashmap, ctx);
	}

	return 0;
}

static void _print_site_stats(FILE *fp)
{
	struct site_stats ctx = { .fp = fp};

	wget_thread_mutex_lock(hosts_mutex);
	wget_hashmap_browse(hosts, (wget_hashmap_browse_t) hosts_hashmap, &ctx);
	wget_thread_mutex_unlock(hosts_mutex);
}

static int print_treeish(struct site_stats *ctx, TREE_DOCS *node)
{
	if (node) {
		if (ctx->level) {
			for (int i = 0; i < ctx->level - 1; i++)
				fprintf(ctx->fp, "|   ");
			if (node->redirect)
				fprintf(ctx->fp, ":..");
			else
				fprintf(ctx->fp, "|--");
		}

		fprintf(ctx->fp, "%s\n", node->iri->uri);

		if (node->children) {
			ctx->level++;
			wget_vector_browse(node->children, (wget_vector_browse_t) print_treeish, ctx);
			ctx->level--;
		}
	}

	return 0;
}

static int hosts_hashmap_tree(struct site_stats *ctx, HOST *host)
{
	if (host->tree_docs && host->root) {
		fprintf(ctx->fp, "\n  %s://%s:\n", host->scheme, host->host);
		print_treeish(ctx, host->root);
	}

	return 0;
}

static void stats_print_csv_site_entry(struct site_stats_cvs_json *ctx, TREE_DOCS *node)
{
	long long transfer_time = node->doc->response_end - node->doc->request_start;
	fprintf(ctx->fp, "%s,%d,%d,%d,%d,%lld,%lld,%lld,%lld,%d,%s,%d,%d,%d,%d\n",
			node->iri->uri, node->doc->status, ctx->id, ctx->parent_id, !node->redirect,
			node->doc->size_downloaded, node->doc->size_decompressed, transfer_time,
			node->doc->initial_response_duration, node->doc->encoding,
			node->doc->is_sig ? "true" : "false", node->doc->valid_sigs,
			node->doc->invalid_sigs, node->doc->missing_sigs, node->doc->bad_sigs);
}

static void stats_print_json_site_entry(struct site_stats_cvs_json *ctx, TREE_DOCS *node)
{
	if (ctx->id > 1)
		fprintf(ctx->fp, ",\n");

	long long transfer_time = node->doc->response_end - node->doc->request_start;
	int ntabs = ctx->ntabs + 1;

	fprintf(ctx->fp, "%.*s\"URL\" : \"%s\",\n", ntabs, tabs, node->iri->uri);
	fprintf(ctx->fp, "%.*s\"Status\" : %d,\n", ntabs, tabs, node->doc->status);
	fprintf(ctx->fp, "%.*s\"ID\" : %d,\n", ntabs, tabs, ctx->id);
	fprintf(ctx->fp, "%.*s\"ParentID\" : %d,\n", ntabs, tabs, ctx->parent_id);
	fprintf(ctx->fp, "%.*s\"Link\" : %d,\n", ntabs, tabs, !node->redirect);
	fprintf(ctx->fp, "%.*s\"Size\" : %lld,\n", ntabs, tabs, node->doc->size_downloaded);
	fprintf(ctx->fp, "%.*s\"SizeDecompressed\" : %lld,\n", ntabs, tabs, node->doc->size_decompressed);
	fprintf(ctx->fp, "%.*s\"TransferTime\" : %lld,\n", ntabs, tabs, transfer_time);
	fprintf(ctx->fp, "%.*s\"ResponseTime\" : %lld,\n", ntabs, tabs, node->doc->initial_response_duration);
	if (node->doc->is_sig) {
		fprintf(ctx->fp, "%.*s\"GPG\" : {\n", ntabs, tabs);
		fprintf(ctx->fp, "%.*s\"Valid\" : %d,\n", ntabs + 1, tabs, node->doc->valid_sigs);
		fprintf(ctx->fp, "%.*s\"Invalid\" : %d,\n", ntabs + 1, tabs, node->doc->invalid_sigs);
		fprintf(ctx->fp, "%.*s\"Missing\" : %d,\n", ntabs + 1, tabs, node->doc->missing_sigs);
		fprintf(ctx->fp, "%.*s\"Bad\" : %d\n", ntabs + 1, tabs, node->doc->bad_sigs);
		fprintf(ctx->fp, "%.*s},\n", ntabs, tabs);
	}
	fprintf(ctx->fp, "%.*s\"Encoding\" : \"%d\"\n", ntabs, tabs, node->doc->encoding);
}

static int print_csv_json(struct site_stats_cvs_json *ctx, TREE_DOCS *node)
{
	if (node) {
		ctx->id++;

		if (ctx->format == WGET_STATS_FORMAT_CSV)
			stats_print_csv_site_entry(ctx, node);
		else  if (ctx->format == WGET_STATS_FORMAT_JSON)
			stats_print_json_site_entry(ctx, node);

		if (node->children) {
			int parent_id = ctx->parent_id;
			ctx->parent_id = ctx->id;
			wget_vector_browse(node->children, (wget_vector_browse_t) print_csv_json, ctx);
			ctx->parent_id = parent_id;
		}
	}

	return 0;
}

static int hosts_hashmap_csv_json(struct site_stats_cvs_json *ctx, HOST *host)
{
	if (host->tree_docs && host->root) {
		ctx->host = host;
		print_csv_json(ctx, host->root);
	}
	return 0;
}

static void print_site_stats_csv_json(FILE *fp, wget_stats_format_t format, int ntabs)
{
	struct site_stats_cvs_json ctx = { .fp = fp, .format = format, .ntabs = ntabs};

	wget_thread_mutex_lock(hosts_mutex);
	wget_hashmap_browse(hosts, (wget_hashmap_browse_t) hosts_hashmap_csv_json, &ctx);
	wget_thread_mutex_unlock(hosts_mutex);

	if (format == WGET_STATS_FORMAT_JSON)
		fprintf(ctx.fp, "\n");
}

G_GNUC_WGET_PURE static const char *stats_server_hpkp(wget_hpkp_stats_t hpkp)
{
	switch (hpkp) {
	case WGET_STATS_HPKP_NO:
		return "HPKP_NO";
	case WGET_STATS_HPKP_MATCH:
		return "HPKP_MATCH";
	case WGET_STATS_HPKP_NOMATCH:
		return "HPKP_NOMATCH";
	case WGET_STATS_HPKP_ERROR:
		return "HPKP_ERROR";
	default:
		error_printf(_("Unknown HPKP stats type %d\n"), (int) hpkp);
		return "-";
	}
}

static void stats_print_human_tls_entry(struct json_stats *ctx, const tls_stats_t *tls_stats)
{
	fprintf(ctx->fp, "  %s:\n", tls_stats->hostname);
	fprintf(ctx->fp, "    Version         : %s\n", tls_stats->version);
	fprintf(ctx->fp, "    False Start     : %s\n", ON_OFF_DASH(tls_stats->false_start));
	fprintf(ctx->fp, "    TFO             : %s\n", ON_OFF_DASH(tls_stats->tfo));
	fprintf(ctx->fp, "    ALPN Protocol   : %s\n", tls_stats->alpn_proto);
	fprintf(ctx->fp, "    Resumed         : %s\n", YES_NO(tls_stats->resumed));
	fprintf(ctx->fp, "    TCP Protocol    : %s\n", HTTP_1_2(tls_stats->tcp_protocol));
	fprintf(ctx->fp, "    Cert Chain Size : %d\n", tls_stats->cert_chain_size);
	fprintf(ctx->fp, "    TLS negotiation\n");
	fprintf(ctx->fp, "    duration (ms)   : %lld\n\n", tls_stats->millisecs);
}

static void stats_print_json_tls_entry(struct json_stats *ctx, const tls_stats_t *tls_stats)
{
	fprintf(ctx->fp, "%.*s{\n", ctx->ntabs + 1, tabs);
	fprintf(ctx->fp, "%.*s\"Hostname\" : \"%s\",\n", ctx->ntabs + 2, tabs, tls_stats->hostname);
	fprintf(ctx->fp, "%.*s\"TLSVersion\" : \"%s\",\n", ctx->ntabs + 2, tabs, tls_stats->version);
	fprintf(ctx->fp, "%.*s\"FalseStart\" : \"%s\",\n", ctx->ntabs + 2, tabs, ON_OFF_DASH(tls_stats->false_start));
	fprintf(ctx->fp, "%.*s\"TFO\" : \"%s\",\n", ctx->ntabs + 2, tabs, ON_OFF_DASH(tls_stats->tfo));
	fprintf(ctx->fp, "%.*s\"ALPN\" : \"%s\",\n", ctx->ntabs + 2, tabs, tls_stats->alpn_proto);
	fprintf(ctx->fp, "%.*s\"Resumed\" : \"%s\",\n", ctx->ntabs + 2, tabs, YES_NO(tls_stats->resumed));
	fprintf(ctx->fp, "%.*s\"HTTPVersion\" : \"%s\",\n", ctx->ntabs + 2, tabs, HTTP_1_2(tls_stats->tcp_protocol));
	fprintf(ctx->fp, "%.*s\"Certificates\" : %d,\n", ctx->ntabs + 2, tabs, tls_stats->cert_chain_size);
	fprintf(ctx->fp, "%.*s\"Duration\" : %lld\n", ctx->ntabs + 2, tabs, tls_stats->millisecs);
	if (ctx->last)
		fprintf(ctx->fp, "%.*s}\n", ctx->ntabs + 1, tabs);
	else
		fprintf(ctx->fp, "%.*s},\n", ctx->ntabs + 1, tabs);
}

static void stats_print_csv_tls_entry(struct json_stats *ctx, const tls_stats_t *tls_stats)
{
	fprintf(ctx->fp, "%s,%s,%s,%s,%s,%s,%s,%d,%lld\n",
		tls_stats->hostname,
		tls_stats->version,
		ONE_ZERO_DASH(tls_stats->false_start),
		ONE_ZERO_DASH(tls_stats->tfo),
		tls_stats->alpn_proto,
		tls_stats->resumed ? "1" : "0",
		tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_1_1 ?
			"1" : (tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_2_0 ? "2" : "-"),
		tls_stats->cert_chain_size,
		tls_stats->millisecs);
}

static void stats_print_human_server_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	fprintf(ctx->fp, "  %s:\n", server_stats->hostname);
	fprintf(ctx->fp, "    IP             : %s\n", server_stats->ip);
	fprintf(ctx->fp, "    Scheme         : %s\n", server_stats->scheme);
	fprintf(ctx->fp, "    HPKP           : %s\n", stats_server_hpkp(server_stats->hpkp));
	fprintf(ctx->fp, "    HPKP New Entry : %s\n", ON_OFF_DASH(server_stats->hpkp_new));
	fprintf(ctx->fp, "    HSTS           : %s\n", ON_OFF_DASH(server_stats->hsts));
	fprintf(ctx->fp, "    CSP            : %s\n\n", ON_OFF_DASH(server_stats->csp));
}

static void stats_print_json_server_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	fprintf(ctx->fp, "%.*s{\n", ctx->ntabs + 1, tabs);
	fprintf(ctx->fp, "%.*s\"Hostname\" : \"%s\",\n", ctx->ntabs + 2, tabs, server_stats->hostname);
	fprintf(ctx->fp, "%.*s\"IP\" : \"%s\",\n", ctx->ntabs + 2, tabs, server_stats->ip);
	fprintf(ctx->fp, "%.*s\"Scheme\" : \"%s\",\n", ctx->ntabs + 2, tabs, HTTP_S_DASH(server_stats->scheme));
	fprintf(ctx->fp, "%.*s\"HPKP\" : \"%s\",\n", ctx->ntabs + 2, tabs, stats_server_hpkp(server_stats->hpkp));
	fprintf(ctx->fp, "%.*s\"NewHPKP\" : \"%s\",\n", ctx->ntabs + 2, tabs, ON_OFF_DASH(server_stats->hpkp_new));
	fprintf(ctx->fp, "%.*s\"HSTS\" : \"%s\",\n", ctx->ntabs + 2, tabs, ON_OFF_DASH(server_stats->hsts));
	fprintf(ctx->fp, "%.*s\"CSP\" : \"%s\"\n", ctx->ntabs + 2, tabs, ON_OFF_DASH(server_stats->csp));
	if (ctx->last)
		fprintf(ctx->fp, "%.*s}\n", ctx->ntabs + 1, tabs);
	else
		fprintf(ctx->fp, "%.*s},\n", ctx->ntabs + 1, tabs);
}

static void stats_print_csv_server_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	fprintf(ctx->fp, "%s,%s,%s,%s,%s,%s,%s\n",
		server_stats->hostname,
		server_stats->ip,
		HTTP_S_DASH(server_stats->scheme),
		stats_server_hpkp(server_stats->hpkp),
		ONE_ZERO_DASH(server_stats->hpkp_new),
		ONE_ZERO_DASH(server_stats->hsts),
		ONE_ZERO_DASH(server_stats->csp));
}

static void stats_print_human_ocsp_entry(struct json_stats *ctx, const ocsp_stats_t *ocsp_stats)
{
	fprintf(ctx->fp, "  %s:\n", ocsp_stats->hostname);
	fprintf(ctx->fp, "    Valid          : %d\n", ocsp_stats->nvalid);
	fprintf(ctx->fp, "    Revoked        : %d\n", ocsp_stats->nrevoked);
	fprintf(ctx->fp, "    Ignored        : %d\n\n", ocsp_stats->nignored);
}

static void stats_print_json_ocsp_entry(struct json_stats *ctx, const ocsp_stats_t *ocsp_stats)
{
	fprintf(ctx->fp, "%.*s{\n", ctx->ntabs + 1, tabs);
	fprintf(ctx->fp, "%.*s\"Hostname\" : \"%s\",\n", ctx->ntabs + 2, tabs, ocsp_stats->hostname);
	fprintf(ctx->fp, "%.*s\"Valid\" : %d,\n", ctx->ntabs + 2, tabs, ocsp_stats->nvalid);
	fprintf(ctx->fp, "%.*s\"Revoked\" : %d,\n", ctx->ntabs + 2, tabs, ocsp_stats->nrevoked);
	fprintf(ctx->fp, "%.*s\"Ignored\" : %d\n", ctx->ntabs + 2, tabs, ocsp_stats->nignored);
	if (ctx->last)
		fprintf(ctx->fp, "%.*s}\n", ctx->ntabs + 1, tabs);
	else
		fprintf(ctx->fp, "%.*s},\n", ctx->ntabs + 1, tabs);
}

static void stats_print_csv_ocsp_entry(struct json_stats *ctx, const ocsp_stats_t *ocsp_stats)
{
	fprintf(ctx->fp, "%s,%d,%d,%d\n",
		ocsp_stats->hostname, ocsp_stats->nvalid, ocsp_stats->nrevoked, ocsp_stats->nignored);
}

static void stats_print_tree(FILE *fp)
{
	struct site_stats ctx = { .fp = fp};

	wget_thread_mutex_lock(hosts_mutex);
	wget_hashmap_browse(hosts, (wget_hashmap_browse_t) hosts_hashmap_tree, &ctx);
	wget_thread_mutex_unlock(hosts_mutex);
}

void stats_print_data(const wget_vector_t *v, wget_vector_browse_t browse, FILE *fp, int ntabs)
{
	struct json_stats ctx = { .fp = fp, .ntabs = ntabs };

	for (int it = 0; it < wget_vector_size(v); it++) {
		if (it == wget_vector_size(v) - 1)
				ctx.last = true;
		browse(&ctx, wget_vector_get(v, it));
	}
}

static void stats_print_ocsp_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nOCSP Statistics:\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_human_ocsp_entry, fp, 0);
}

static void stats_print_ocsp_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,Valid,Revoked,Ignored\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_csv_ocsp_entry, fp, 0);
}

static void stats_print_ocsp_json(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\t\"OCSP Statistics\": [{\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_json_ocsp_entry, fp, 0);
	fprintf(fp, "\t}]\n");
}

static void stats_print_server_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nServer Statistics:\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_human_server_entry, fp, 0);
}

static void stats_print_server_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,IP,Scheme,HPKP,NewHPKP,HSTS,CSP\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_csv_server_entry, fp, 0);
}

static void stats_print_server_json(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\t\"Server Statistics\": [{\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_json_server_entry, fp, 0);
	fprintf(fp, "\t}]\n");
}

static void stats_print_site_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nSite Statistics:\n");
	_print_site_stats(fp);
}

static void stats_print_site_csv(stats_opts_t *opts, FILE *fp)
{
	print_site_stats_csv_json(fp, opts->format, 0);
}

static void stats_print_site_json(stats_opts_t *opts, FILE *fp)
{
	print_site_stats_csv_json(fp, opts->format, 0);
}

static void stats_print_site_tree(stats_opts_t *opts, FILE *fp)
{
	stats_print_tree(fp);
}

static void stats_print_tls_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nTLS Statistics:\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_human_tls_entry, fp, 0);
}

static void stats_print_tls_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,TLSVersion,FalseStart,TFO,ALPN,Resumed,HTTPVersion,Certificates,Duration\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_csv_tls_entry, fp, 0);
}

static void stats_print_tls_json(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\t\"TLS Statistics\": [{\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_json_tls_entry, fp, 0);
	fprintf(fp, "\t}]\n");
}

void stats_print(void)
{
	FILE *fp;

	for (unsigned it = 0; it < countof(stats_opts); it++) {
		stats_opts_t *opts = stats_opts[it];

		if (!*opts->options)
			continue;

		const char *filename = opts->file;

		if (filename && *filename && wget_strcmp(filename, "-") && !config.dont_write) {
			// TODO: think about & fix this
			if (config.stats_all && opts->format != WGET_STATS_FORMAT_CSV && it == 0)
				fp = fopen(filename, "a");
			else
				fp = fopen(filename, "w");
		} else if (filename && *filename && !wget_strcmp(filename, "-") && !config.dont_write) {
			fp = stdout;
		} else {
			fp = stderr;
		}

		if (!fp) {
			error_printf(_("File could not be opened %s for %s stats\n"), filename, opts->tag);
			continue;
		}

		opts->print[opts->format](opts, fp);

		if (fp != stderr && fp != stdout) {
			info_printf(_("%s stats saved in %s\n"), stats_opts[type].tag, filename);
			fclose(fp);
		}
	}
}

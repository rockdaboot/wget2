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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"
#include "wget_host.h"

#define NULL_TO_DASH(s) ((s) ? (s) : "-")

static wget_vector_t
	*dns_stats_v,
	*tls_stats_v,
	*server_stats_v,
	*ocsp_stats_v;

static wget_thread_mutex_t
	dns_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	tls_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	server_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	ocsp_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	host_docs_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	tree_docs_mutex = WGET_THREAD_MUTEX_INITIALIZER,
	*hosts_mutex;

typedef struct {
	const char
		*tag,
		*file;
	wget_stats_format_t
		format;
	bool
		status : 1;
} stats_opts_t;

static stats_opts_t
	stats_opts[] = {
		[WGET_STATS_TYPE_DNS] = { .tag = "DNS" },
		[WGET_STATS_TYPE_TLS] = { .tag = "TLS" },
		[WGET_STATS_TYPE_SERVER] = { .tag = "Server" },
		[WGET_STATS_TYPE_OCSP] = { .tag = "OCSP" },
		[WGET_STATS_TYPE_SITE] = { .tag = "Site" },
	};

static wget_hashmap_t
	*hosts;

void stats_set_hosts(wget_hashmap_t *_hosts, wget_thread_mutex_t *_hosts_mutex)
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

static int _tree_docs_compare(const TREE_DOCS *tree_docsp1, const TREE_DOCS *tree_docsp2)
{
	return wget_iri_compare(tree_docsp1->iri, tree_docsp2->iri);
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
static unsigned int _tree_docs_hash(const TREE_DOCS *tree_docsp)
{
	unsigned int h = tree_docsp->iri->port; // use port as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	for (p = (unsigned char *)tree_docsp->iri->scheme; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)tree_docsp->iri->host; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)tree_docsp->iri->path; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)tree_docsp->iri->query; p && *p; p++)
		h = h * 101 + *p;

	return h;
}

static void _free_host_docs_entry(HOST_DOCS *host_docsp)
{
	if (host_docsp) {
		wget_vector_free(&host_docsp->docs);
		wget_xfree(host_docsp);
	}
}

static void _free_tree_docs_entry(TREE_DOCS *tree_docsp)
{
	if (tree_docsp) {
		wget_vector_deinit(tree_docsp->children);
		wget_xfree(tree_docsp->children);
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
	wget_hashmap_t *host_docs;
	HOST_DOCS *host_docsp;
	wget_vector_t *docs;
	DOC *doc;
	HOST *hostp;

	if (!(hostp = stats_host_get(iri))) {
		error_printf("No existing host entry for iri->uri = %s\n", iri->uri);
		return NULL;
	}

	wget_thread_mutex_lock(&host_docs_mutex);

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
		docs = wget_vector_create(8, -2, NULL);
		host_docsp->docs = docs;
	}

	doc = wget_calloc(1, sizeof(DOC));
	doc->iri = iri;
	doc->size_downloaded = resp->cur_downloaded;
	doc->size_decompressed = resp->body->length;
	doc->encoding = resp->content_encoding;
	wget_vector_add_noalloc(docs, doc);

	wget_thread_mutex_unlock(&host_docs_mutex);

	return doc;
}

static TREE_DOCS *stats_tree_docs_get(wget_hashmap_t *tree_docs, wget_iri_t *iri)
{
	TREE_DOCS *tree_docsp = NULL, tree_doc = {.iri = iri};

	if (tree_docs)
		tree_docsp = wget_hashmap_get(tree_docs, &tree_doc);

	return tree_docsp;
}

TREE_DOCS *stats_tree_docs_add(wget_iri_t *parent_iri, wget_iri_t *iri, bool robot_iri, bool redirect, DOC *doc)
{
	HOST *hostp = NULL;
	wget_hashmap_t *tree_docs;
	TREE_DOCS *parent_node, *child_node = NULL;
	wget_vector_t *children = NULL;

	if (!doc)
		return NULL;

	if (parent_iri && !(hostp = stats_host_get(parent_iri))) {
		error_printf("No existing host entry for parent_iri->uri = %s\n", parent_iri->uri);
		return NULL;
	}

	wget_thread_mutex_lock(&tree_docs_mutex);

	if (parent_iri) {
		if (!(parent_node = stats_tree_docs_get(hostp->tree_docs, parent_iri))) {
			error_printf("No existing entry for %s in tree_docs hashmap\n", parent_iri->uri);
			goto out;
		}

		if (!(children = parent_node->children))
			children = parent_node->children = wget_vector_create(8, -2, NULL);
	}

	if (!(hostp = stats_host_get(iri))) {
		error_printf("No existing host entry for iri->uri = %s\n", iri->uri);
		goto out;
	}

	if (!(tree_docs = hostp->tree_docs)) {
		hostp->tree_docs = tree_docs = wget_hashmap_create(16, (wget_hashmap_hash_t)_tree_docs_hash, (wget_hashmap_compare_t)_tree_docs_compare);
		wget_hashmap_set_key_destructor(tree_docs, (wget_hashmap_key_destructor_t)_free_tree_docs_entry);
	}

	if (!(child_node = stats_tree_docs_get(tree_docs, iri))) {
		child_node = wget_calloc(1, sizeof(TREE_DOCS));
		child_node->iri = iri;
		child_node->doc = doc;
		child_node->children = NULL;
		child_node->redirect = redirect;
		wget_hashmap_put_noalloc(tree_docs, child_node, child_node);
	} else
		error_printf("Existing entry for iri->uri = %s in tree_docs hashmap of host %s://%s\n", iri->uri, hostp->scheme, hostp->host);

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
	wget_thread_mutex_unlock(&tree_docs_mutex);

	return child_node;
}


static void stats_callback(wget_stats_type_t type, const void *stats)
{
	switch(type) {
	case WGET_STATS_TYPE_DNS: {
		dns_stats_t dns_stats = { .millisecs = -1, .port = -1 };

		dns_stats.host = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_HOST, stats));
		dns_stats.ip = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_IP, stats));

		if (wget_tcp_get_stats_dns(WGET_STATS_DNS_PORT, stats))
			dns_stats.port = *((uint16_t *)wget_tcp_get_stats_dns(WGET_STATS_DNS_PORT, stats));

		if (wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats))
			dns_stats.millisecs = *((long long *)wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats));

		wget_thread_mutex_lock(&dns_mutex);
		wget_vector_add(dns_stats_v, &dns_stats, sizeof(dns_stats_t));
		wget_thread_mutex_unlock(&dns_mutex);

		break;
	}

	case WGET_STATS_TYPE_TLS: {
		tls_stats_t tls_stats = { .resumed = -1, .tcp_protocol = -1, .millisecs = -1, .cert_chain_size = -1, .tls_con = -1 };

		tls_stats.hostname = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_HOSTNAME, stats));
		tls_stats.version = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats));
		tls_stats.false_start = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats));
		tls_stats.tfo = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats));
		tls_stats.alpn_proto = wget_strdup(wget_tcp_get_stats_tls(WGET_STATS_TLS_ALPN_PROTO, stats));

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

		wget_thread_mutex_lock(&tls_mutex);
		wget_vector_add(tls_stats_v, &tls_stats, sizeof(tls_stats_t));
		wget_thread_mutex_unlock(&tls_mutex);

		break;
	}

	case WGET_STATS_TYPE_SERVER: {
		server_stats_t server_stats = { .hpkp = WGET_STATS_HPKP_NO };

		server_stats.hostname = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HOSTNAME, stats));
		server_stats.ip = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_IP, stats));
		server_stats.scheme = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_SCHEME, stats));
		server_stats.hpkp_new = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP_NEW, stats));
		server_stats.hsts = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HSTS, stats));
		server_stats.csp = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_CSP, stats));

		if (wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats))
			server_stats.hpkp = *((char *)wget_tcp_get_stats_server(WGET_STATS_SERVER_HPKP, stats));

		wget_thread_mutex_lock(&server_mutex);
		wget_vector_add(server_stats_v, &server_stats, sizeof(server_stats_t));
		wget_thread_mutex_unlock(&server_mutex);

		break;
	}

	case WGET_STATS_TYPE_OCSP: {
		ocsp_stats_t ocsp_stats = { .nvalid = -1, .nrevoked = -1, .nignored = -1 };

		ocsp_stats.hostname = wget_strdup(wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_HOSTNAME, stats));

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats))
			ocsp_stats.nvalid = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats));

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats))
			ocsp_stats.nrevoked = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats));

		if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats))
			ocsp_stats.nignored = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats));

		wget_thread_mutex_lock(&ocsp_mutex);
		wget_vector_add(ocsp_stats_v, &ocsp_stats, sizeof(ocsp_stats_t));
		wget_thread_mutex_unlock(&ocsp_mutex);

		break;
	}

	case WGET_STATS_TYPE_SITE: {
		break;
	}

	default:
		error_printf("Unknown stats type %d\n", (int) type);
		break;
	}
}

static void free_dns_stats(dns_stats_t *stats)
{
	if (stats) {
		xfree(stats->host);
		xfree(stats->ip);
	}
}

static void free_tls_stats(tls_stats_t *stats)
{
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->version);
		xfree(stats->false_start);
		xfree(stats->tfo);
		xfree(stats->alpn_proto);
	}
}

static void free_server_stats(server_stats_t *stats)
{
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->ip);
		xfree(stats->scheme);
		xfree(stats->hsts);
		xfree(stats->csp);
		xfree(stats->hpkp_new);
	}
}

static void free_ocsp_stats(server_stats_t *stats)
{
	if (stats)
		xfree(stats->hostname);
}

void stats_set_option(int type, bool status, int format, const char *filename)
{
	if (type < 0 || type >= (int) countof(stats_opts))
		return;

	stats_opts_t *opts = &stats_opts[type];
	opts->status = status;
	opts->format = (wget_stats_format_t) format;

	xfree(opts->file);
	opts->file = filename;
}

bool stats_is_enabled(int type)
{
	if (type < 0 || type >= (int) countof(stats_opts))
		return false;

	return stats_opts[type].status;
}

void stats_init(void)
{
	if (stats_opts[WGET_STATS_TYPE_DNS].status) {
		dns_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(dns_stats_v, (wget_vector_destructor_t) free_dns_stats);
		wget_tcp_set_stats_dns(stats_callback);
	}

	if (stats_opts[WGET_STATS_TYPE_TLS].status) {
		tls_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(tls_stats_v, (wget_vector_destructor_t) free_tls_stats);
		wget_tcp_set_stats_tls(stats_callback);
	}

	if (stats_opts[WGET_STATS_TYPE_SERVER].status) {
		server_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(server_stats_v, (wget_vector_destructor_t) free_server_stats);
		wget_tcp_set_stats_server(stats_callback);
	}

	if (stats_opts[WGET_STATS_TYPE_OCSP].status) {
		ocsp_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(ocsp_stats_v, (wget_vector_destructor_t) free_ocsp_stats);
		wget_tcp_set_stats_ocsp(stats_callback);
	}
}

void stats_exit(void)
{
	wget_vector_free(&dns_stats_v);
	wget_vector_free(&tls_stats_v);
	wget_vector_free(&server_stats_v);
	wget_vector_free(&ocsp_stats_v);

	for (unsigned it = 0; it < countof(stats_opts); it++) {
		xfree(stats_opts[it].file);
	}
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

static int host_docs_hashmap(struct site_stats *ctx, HOST_DOCS *host_docsp)
{
	wget_buffer_printf_append(ctx->buf, "  %8d  %13d\n", host_docsp->http_status, wget_vector_size(host_docsp->docs));

	for (int it = 0; it < wget_vector_size(host_docsp->docs); it++) {
		const DOC *doc = wget_vector_get(host_docsp->docs, it);
		wget_buffer_printf_append(ctx->buf, "         %s  %lld bytes (%s) : ",
				doc->iri->uri,
				doc->size_downloaded,
				print_encoding(doc->encoding));
		wget_buffer_printf_append(ctx->buf, "%lld bytes (decompressed)\n",
				doc->size_decompressed);
	}

	if (ctx->buf->length > 64*1024) {
		fprintf(ctx->fp, "%s", ctx->buf->data);
		wget_buffer_reset(ctx->buf);
	}

	return  0;
}

static int hosts_hashmap(struct site_stats *ctx, HOST *host)
{
	if (host->host_docs) {
		wget_buffer_printf_append(ctx->buf, "\n  %s://%s:\n", host->scheme, host->host);
		wget_buffer_printf_append(ctx->buf, "  %8s  %13s\n", "Status", "No. of docs");

		wget_hashmap_browse(host->host_docs, (wget_hashmap_browse_t)host_docs_hashmap, ctx);
	}

	return 0;
}

static int print_treeish(struct site_stats *ctx, TREE_DOCS *node)
{
	if (node) {
		if (ctx->level) {
			for (int i = 0; i < ctx->level - 1; i++)
				wget_buffer_printf_append(ctx->buf, "|   ");
			if (node->redirect)
				wget_buffer_printf_append(ctx->buf, ":..");
			else
				wget_buffer_printf_append(ctx->buf, "|--");
		}

		wget_buffer_printf_append(ctx->buf, "%s\n", node->iri->uri);

		if (ctx->buf->length > 64*1024) {
			fprintf(ctx->fp, "%s", ctx->buf->data);
			wget_buffer_reset(ctx->buf);
		}

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
		wget_buffer_printf_append(ctx->buf, "\n  %s://%s:\n", host->scheme, host->host);
		print_treeish(ctx, host->root);
	}

	return 0;
}

static void _print_site_stats(wget_buffer_t *buf, FILE *fp)
{
	struct site_stats ctx = { .buf = buf, .fp = fp};

	wget_thread_mutex_lock(hosts_mutex);
	wget_hashmap_browse(hosts, (wget_hashmap_browse_t) hosts_hashmap, &ctx);
	wget_thread_mutex_unlock(hosts_mutex);

	fprintf(fp, "%s", buf->data);

	wget_buffer_reset(ctx.buf);

	wget_thread_mutex_lock(hosts_mutex);
	wget_hashmap_browse(hosts, (wget_hashmap_browse_t) hosts_hashmap_tree, &ctx);
	wget_thread_mutex_unlock(hosts_mutex);

	fprintf(fp, "%s", buf->data);
}

static void stats_print_csv_site_entry(struct site_stats_cvs_json *ctx, TREE_DOCS *node)
{
	wget_buffer_printf_append(ctx->buf, "%s://%s,%s,%d,%d,%d,%lld,%lld,%d\n",
			ctx->host->scheme, ctx->host->host, node->iri->uri, ctx->id, ctx->parent_id, !node->redirect,
			node->doc->size_downloaded, node->doc->size_decompressed, node->doc->encoding);

}

static void stats_print_json_site_entry(struct site_stats_cvs_json *ctx, TREE_DOCS *node)
{
	if (ctx->id > 1)
		wget_buffer_printf_append(ctx->buf, ",\n");
	wget_buffer_printf_append(ctx->buf, "\t{\n");
	wget_buffer_printf_append(ctx->buf, "\t\t\"Host\" : \"%s://%s\",\n", ctx->host->scheme, ctx->host->host);
	wget_buffer_printf_append(ctx->buf, "\t\t\"IRI\" : \"%s\",\n", node->iri->uri);
	wget_buffer_printf_append(ctx->buf, "\t\t\"ID\" : %d,\n", ctx->id);
	wget_buffer_printf_append(ctx->buf, "\t\t\"ParentID\" : %d,\n", ctx->parent_id);
	wget_buffer_printf_append(ctx->buf, "\t\t\"Link\" : %d,\n", !node->redirect);
	wget_buffer_printf_append(ctx->buf, "\t\t\"Size\" : %lld,\n", node->doc->size_downloaded);
	wget_buffer_printf_append(ctx->buf, "\t\t\"SizeDecompressed\" : %lld,\n", node->doc->size_decompressed);
	wget_buffer_printf_append(ctx->buf, "\t\t\"Encoding\" : \"%d\"\n", node->doc->encoding);
	wget_buffer_printf_append(ctx->buf, "\t}");

}

static int print_csv_json(struct site_stats_cvs_json *ctx, TREE_DOCS *node)
{
	if (node) {
		ctx->id++;

		if (ctx->format == WGET_STATS_FORMAT_CSV)
			stats_print_csv_site_entry(ctx, node);
		else  if (ctx->format == WGET_STATS_FORMAT_JSON)
			stats_print_json_site_entry(ctx, node);

		if (ctx->buf->length > 64*1024) {
			fprintf(ctx->fp, "%s", ctx->buf->data);
			wget_buffer_reset(ctx->buf);
		}

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

static void print_site_stats_csv_json(wget_buffer_t *buf, FILE *fp, wget_stats_format_t format)
{
	struct site_stats_cvs_json ctx = { .buf = buf, .fp = fp, .format = format};

	wget_thread_mutex_lock(hosts_mutex);
	wget_hashmap_browse(hosts, (wget_hashmap_browse_t) hosts_hashmap_csv_json, &ctx);
	wget_thread_mutex_unlock(hosts_mutex);

	if (format == WGET_STATS_FORMAT_JSON)
		wget_buffer_printf_append(ctx.buf, "\n");

	fprintf(fp, "%s", buf->data);
}

G_GNUC_WGET_PURE static const char *stats_server_hpkp(wget_hpkp_stats_t hpkp)
{
	switch (hpkp) {
	case WGET_STATS_HPKP_NO:
		return "No existing entry in hpkp db";
	case WGET_STATS_HPKP_MATCH:
		return "Pubkey pinning matched";
	case WGET_STATS_HPKP_NOMATCH:
		return "Pubkey pinning mismatch";
	case WGET_STATS_HPKP_ERROR:
		return "Pubkey pinning error";
	default:
		error_printf("Unknown HPKP stats type %d\n", (int) hpkp);
		return "-";
	}
}

static void stats_print_human_dns_entry(struct json_stats *ctx, const dns_stats_t *dns_stats)
{
	wget_buffer_printf_append(ctx->buf, "  %4lld %s:%hu (%s)\n",
		dns_stats->millisecs,
		NULL_TO_DASH(dns_stats->host),
		dns_stats->port,
		NULL_TO_DASH(dns_stats->ip));
}

static void stats_print_json_dns_entry(struct json_stats *ctx, const dns_stats_t *dns_stats)
{
	wget_buffer_printf_append(ctx->buf, "\t{\n");
	wget_buffer_printf_append(ctx->buf, "\t\t\"Hostname\" : \"%s\",\n", NULL_TO_DASH(dns_stats->host));
	wget_buffer_printf_append(ctx->buf, "\t\t\"IP\" : \"%s\",\n", NULL_TO_DASH(dns_stats->ip));
	wget_buffer_printf_append(ctx->buf, "\t\t\"Port\" : %hu,\n", dns_stats->port);
	wget_buffer_printf_append(ctx->buf, "\t\t\"Duration\" : %lld\n", dns_stats->millisecs);
	if (ctx->last)
		wget_buffer_printf_append(ctx->buf, "\t}\n");
	else
		wget_buffer_printf_append(ctx->buf, "\t},\n");
}

static void stats_print_csv_dns_entry(struct json_stats *ctx, const dns_stats_t *dns_stats)
{
	wget_buffer_printf_append(ctx->buf, "%s,%s,%hu,%lld\n",
		NULL_TO_DASH(dns_stats->host),
		NULL_TO_DASH(dns_stats->ip),
		dns_stats->port,
		dns_stats->millisecs);
}

static void stats_print_human_tls_entry(struct json_stats *ctx, const tls_stats_t *tls_stats)
{
	wget_buffer_printf_append(ctx->buf, "  %s:\n", NULL_TO_DASH(tls_stats->hostname));
	wget_buffer_printf_append(ctx->buf, "    Version         : %s\n", NULL_TO_DASH(tls_stats->version));
	wget_buffer_printf_append(ctx->buf, "    False Start     : %s\n", NULL_TO_DASH(tls_stats->false_start));
	wget_buffer_printf_append(ctx->buf, "    TFO             : %s\n", NULL_TO_DASH(tls_stats->tfo));
	wget_buffer_printf_append(ctx->buf, "    ALPN Protocol   : %s\n", NULL_TO_DASH(tls_stats->alpn_proto));
	wget_buffer_printf_append(ctx->buf, "    Resumed         : %s\n",
		tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No");
	wget_buffer_printf_append(ctx->buf, "    TCP Protocol    : %s\n",
		tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_1_1 ?
			"HTTP/1.1" :
			(tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"));
	wget_buffer_printf_append(ctx->buf, "    Cert Chain Size : %d\n", tls_stats->cert_chain_size);
	wget_buffer_printf_append(ctx->buf, "    TLS negotiation\n");
	wget_buffer_printf_append(ctx->buf, "    duration (ms)   : %lld\n\n", tls_stats->millisecs);
}

static void stats_print_json_tls_entry(struct json_stats *ctx, const tls_stats_t *tls_stats)
{
	wget_buffer_printf_append(ctx->buf, "\t{\n");
	wget_buffer_printf_append(ctx->buf, "\t\t\"Hostname\" : \"%s\",\n", NULL_TO_DASH(tls_stats->hostname));
	wget_buffer_printf_append(ctx->buf, "\t\t\"TLSVersion\" : \"%s\",\n", NULL_TO_DASH(tls_stats->version));
	wget_buffer_printf_append(ctx->buf, "\t\t\"FalseStart\" : \"%s\",\n", NULL_TO_DASH(tls_stats->false_start));
	wget_buffer_printf_append(ctx->buf, "\t\t\"TFO\" : \"%s\",\n", NULL_TO_DASH(tls_stats->tfo));
	wget_buffer_printf_append(ctx->buf, "\t\t\"ALPN\" : \"%s\",\n", NULL_TO_DASH(tls_stats->alpn_proto));
	wget_buffer_printf_append(ctx->buf, "\t\t\"Resumed\" : \"%s\",\n",
		tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No");
	wget_buffer_printf_append(ctx->buf, "\t\t\"HTTPVersion\" : \"%s\",\n",
		tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_1_1 ?
			"HTTP/1.1" :
			(tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"));
	wget_buffer_printf_append(ctx->buf, "\t\t\"Certificates\" : %d,\n", tls_stats->cert_chain_size);
	wget_buffer_printf_append(ctx->buf, "\t\t\"Duration\" : %lld\n", tls_stats->millisecs);
	if (ctx->last)
		wget_buffer_printf_append(ctx->buf, "\t}\n");
	else
		wget_buffer_printf_append(ctx->buf, "\t},\n");
}

static void stats_print_csv_tls_entry(struct json_stats *ctx, const tls_stats_t *tls_stats)
{
	wget_buffer_printf_append(ctx->buf, "%s,%s,%s,%s,%s,%s,%s,%d,%lld\n",
		NULL_TO_DASH(tls_stats->hostname),
		NULL_TO_DASH(tls_stats->version),
		NULL_TO_DASH(tls_stats->false_start),
		NULL_TO_DASH(tls_stats->tfo),
		NULL_TO_DASH(tls_stats->alpn_proto),
		tls_stats->resumed ? (tls_stats->resumed == 1 ? "Yes" : "-") : "No",
		tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_1_1 ?
			"HTTP/1.1" :
			(tls_stats->tcp_protocol == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"),
		tls_stats->cert_chain_size,
		tls_stats->millisecs);
}

static void stats_print_human_server_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	wget_buffer_printf_append(ctx->buf, "  %s:\n", NULL_TO_DASH(server_stats->hostname));
	wget_buffer_printf_append(ctx->buf, "    IP             : %s\n", NULL_TO_DASH(server_stats->ip));
	wget_buffer_printf_append(ctx->buf, "    Scheme         : %s\n", NULL_TO_DASH(server_stats->scheme));
	wget_buffer_printf_append(ctx->buf, "    HPKP           : %s\n", stats_server_hpkp(server_stats->hpkp));
	wget_buffer_printf_append(ctx->buf, "    HPKP New Entry : %s\n", NULL_TO_DASH(server_stats->hpkp_new));
	wget_buffer_printf_append(ctx->buf, "    HSTS           : %s\n", NULL_TO_DASH(server_stats->hsts));
	wget_buffer_printf_append(ctx->buf, "    CSP            : %s\n\n", NULL_TO_DASH(server_stats->csp));
}

static void stats_print_json_server_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	wget_buffer_printf_append(ctx->buf, "\t{\n");
	wget_buffer_printf_append(ctx->buf, "\t\t\"Hostname\" : \"%s\",\n", NULL_TO_DASH(server_stats->hostname));
	wget_buffer_printf_append(ctx->buf, "\t\t\"IP\" : \"%s\",\n", NULL_TO_DASH(server_stats->ip));
	wget_buffer_printf_append(ctx->buf, "\t\t\"Scheme\" : \"%s\",\n", NULL_TO_DASH(server_stats->scheme));
	wget_buffer_printf_append(ctx->buf, "\t\t\"HPKP\" : \"%s\",\n", stats_server_hpkp(server_stats->hpkp));
	wget_buffer_printf_append(ctx->buf, "\t\t\"NewHPKP\" : \"%s\",\n", NULL_TO_DASH(server_stats->hpkp_new));
	wget_buffer_printf_append(ctx->buf, "\t\t\"HSTS\" : \"%s\",\n", NULL_TO_DASH(server_stats->hsts));
	wget_buffer_printf_append(ctx->buf, "\t\t\"CSP\" : \"%s\"\n", NULL_TO_DASH(server_stats->csp));
	if (ctx->last)
		wget_buffer_printf_append(ctx->buf, "\t}\n");
	else
		wget_buffer_printf_append(ctx->buf, "\t},\n");
}

static void stats_print_csv_server_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	wget_buffer_printf_append(ctx->buf, "%s,%s,%s,%s,%s,%s,%s\n",
		NULL_TO_DASH(server_stats->hostname),
		NULL_TO_DASH(server_stats->ip),
		NULL_TO_DASH(server_stats->scheme),
		stats_server_hpkp(server_stats->hpkp),
		NULL_TO_DASH(server_stats->hpkp_new),
		NULL_TO_DASH(server_stats->hsts),
		NULL_TO_DASH(server_stats->csp));
}

static void stats_print_human_ocsp_entry(struct json_stats *ctx, const ocsp_stats_t *ocsp_stats)
{
	wget_buffer_printf_append(ctx->buf, "  %s:\n", ocsp_stats->hostname);
	wget_buffer_printf_append(ctx->buf, "    Valid          : %d\n", ocsp_stats->nvalid);
	wget_buffer_printf_append(ctx->buf, "    Revoked        : %d\n", ocsp_stats->nrevoked);
	wget_buffer_printf_append(ctx->buf, "    Ignored        : %d\n\n", ocsp_stats->nignored);
}

static void stats_print_json_ocsp_entry(struct json_stats *ctx, const ocsp_stats_t *ocsp_stats)
{
	wget_buffer_printf_append(ctx->buf, "\t{\n");
	wget_buffer_printf_append(ctx->buf, "\t\t\"Hostname\" : \"%s\",\n", NULL_TO_DASH(ocsp_stats->hostname));
	wget_buffer_printf_append(ctx->buf, "\t\t\"Valid\" : %d,\n", ocsp_stats->nvalid);
	wget_buffer_printf_append(ctx->buf, "\t\t\"Revoked\" : %d,\n", ocsp_stats->nrevoked);
	wget_buffer_printf_append(ctx->buf, "\t\t\"Ignored\" : %d\n", ocsp_stats->nignored);
	if (ctx->last)
		wget_buffer_printf_append(ctx->buf, "\t}\n");
	else
		wget_buffer_printf_append(ctx->buf, "\t},\n");
}

static void stats_print_csv_ocsp_entry(struct json_stats *ctx, const ocsp_stats_t *ocsp_stats)
{
	wget_buffer_printf_append(ctx->buf, "%s,%d,%d,%d\n",
		NULL_TO_DASH(ocsp_stats->hostname), ocsp_stats->nvalid, ocsp_stats->nrevoked, ocsp_stats->nignored);
}

static void _stats_print(const wget_vector_t *v, wget_vector_browse_t browse, wget_buffer_t *buf, FILE *fp)
{
	struct json_stats ctx = { .buf = buf };

	for (int it = 0; it < wget_vector_size(v); it++) {
		if (it == wget_vector_size(v) - 1)
				ctx.last = true;
		browse(&ctx, wget_vector_get(v, it));

		if ((buf->length > 64*1024)) {
			fprintf(fp, "%s", buf->data);
			wget_buffer_reset(buf);
		}
	}

	if (buf->length)
		fprintf(fp, "%s", buf->data);
}

static void stats_print_human(wget_stats_type_t type, wget_buffer_t *buf, FILE *fp)
{
	switch (type) {
	case WGET_STATS_TYPE_DNS:
		wget_buffer_printf(buf, "\nDNS timings:\n");
		wget_buffer_printf_append(buf, "  %4s %s\n", "ms", "Host");
		_stats_print(dns_stats_v, (wget_vector_browse_t) stats_print_human_dns_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_TLS:
		wget_buffer_printf(buf, "\nTLS Statistics:\n");
		_stats_print(tls_stats_v, (wget_vector_browse_t) stats_print_human_tls_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_SERVER:
		wget_buffer_printf(buf, "\nServer Statistics:\n");
		_stats_print(server_stats_v, (wget_vector_browse_t) stats_print_human_server_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_OCSP:
		wget_buffer_printf(buf, "\nOCSP Statistics:\n");
		_stats_print(ocsp_stats_v, (wget_vector_browse_t) stats_print_human_ocsp_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_SITE:
		wget_buffer_printf(buf, "\nSite Statistics:\n");
		_print_site_stats(buf, fp);
		break;

	default:
		error_printf("Unknown stats type %d\n", (int) type);
		break;
	}
}

static void stats_print_json(wget_stats_type_t type, wget_buffer_t *buf, FILE *fp)
{
	wget_buffer_printf(buf, "[\n");

	switch (type) {
	case WGET_STATS_TYPE_DNS:
		_stats_print(dns_stats_v, (wget_vector_browse_t) stats_print_json_dns_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_TLS:
		_stats_print(tls_stats_v, (wget_vector_browse_t) stats_print_json_tls_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_SERVER:
		_stats_print(server_stats_v, (wget_vector_browse_t) stats_print_json_server_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_OCSP:
		_stats_print(ocsp_stats_v, (wget_vector_browse_t) stats_print_json_ocsp_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_SITE:
		print_site_stats_csv_json(buf, fp, WGET_STATS_FORMAT_JSON);
		break;

	default:
		error_printf("Unknown stats type %d\n", (int) type);
		break;
	}

	fprintf(fp, "]\n");
}

static void stats_print_csv(wget_stats_type_t type, wget_buffer_t *buf, FILE *fp)
{
	switch (type) {
	case WGET_STATS_TYPE_DNS:
		wget_buffer_printf(buf, "%s\n", "Hostname,IP,Port,Duration");
		_stats_print(dns_stats_v, (wget_vector_browse_t) stats_print_csv_dns_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_TLS:
		wget_buffer_printf(buf, "%s\n", "Hostname,TLSVersion,FalseStart,TFO,ALPN,Resumed,HTTPVersion,Certificates,Duration");
		_stats_print(tls_stats_v, (wget_vector_browse_t) stats_print_csv_tls_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_SERVER:
		wget_buffer_printf(buf, "%s\n", "Hostname,HPKP,NewHPKP,HSTS,CSP");
		_stats_print(server_stats_v, (wget_vector_browse_t) stats_print_csv_server_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_OCSP:
		wget_buffer_printf(buf, "%s\n", "Hostname,Valid,Revoked,Ignored");
		_stats_print(ocsp_stats_v, (wget_vector_browse_t) stats_print_csv_ocsp_entry, buf, fp);
		break;

	case WGET_STATS_TYPE_SITE:
		wget_buffer_printf_append(buf, "Host,IRI,ID,ParentID,Link,Size,SizeDecompressed,Encoding\n");
		print_site_stats_csv_json(buf, fp, WGET_STATS_FORMAT_CSV);
		break;

	default:
		error_printf("Unknown stats type %d\n", (int) type);
		break;
	}
}

void stats_print(void)
{
	FILE *fp;
	const char *filename;
	wget_buffer_t buf;
	char sbuf[4096];
	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	for (wget_stats_type_t type = 0; (int) type < (int) countof(stats_opts); type++) {
		if (!stats_opts[type].status)
			continue;

		filename = stats_opts[type].file;

		if (filename && *filename && wget_strcmp(filename, "-"))
			fp = fopen(filename, "w");
		else
			fp = stdout;

		if (!fp) {
			error_printf("File could not be opened %s for %s stats\n", filename, stats_opts[type].tag);
			continue;
		}

		switch (stats_opts[type].format) {
		case WGET_STATS_FORMAT_HUMAN:
			stats_print_human(type, &buf, fp);
			break;

		case WGET_STATS_FORMAT_CSV:
			stats_print_csv(type, &buf, fp);
			break;

		case WGET_STATS_FORMAT_JSON:
			stats_print_json(type, &buf, fp);
			break;

		default: error_printf("Unknown stats format %d\n", (int) stats_opts[type].format);
			break;
		}

		if (fp != stdout) {
			info_printf("%s stats saved in %s\n", stats_opts[type].tag, filename);
			fclose(fp);
		}

		wget_buffer_reset(&buf);
	}

	wget_buffer_deinit(&buf);
}

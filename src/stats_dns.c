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
 * DNS statistics functions
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

// Forward declarations for static functions

static void stats_print_dns_human(stats_opts_t *opts, FILE *fp);
static void stats_print_dns_csv(stats_opts_t *opts, FILE *fp);
static void stats_print_dns_json(stats_opts_t *opts, FILE *fp);
static void stats_callback_dns(const void *stats);
static void free_dns_stats(dns_stats_t *stats);

static stats_print_func_t
	print_dns[] = {
		[WGET_STATS_FORMAT_HUMAN] = stats_print_dns_human,
		[WGET_STATS_FORMAT_CSV] = stats_print_dns_csv,
		[WGET_STATS_FORMAT_JSON] = stats_print_dns_json,
	};

stats_opts_t stats_dns_opts = {
	.tag = "DNS",
	.options = &config.stats_dns,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_dns,
	.callback = stats_callback_dns,
	.destructor = (wget_vector_destructor_t) free_dns_stats,
	.print = print_dns,
};

static void stats_callback_dns(const void *stats)
{
	dns_stats_t dns_stats = { .millisecs = -1, .port = -1 };

	dns_stats.host = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_HOST, stats));
	dns_stats.ip = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_IP, stats));

	dns_stats.host = NULL_TO_DASH(dns_stats.host);
	dns_stats.ip = NULL_TO_DASH(dns_stats.ip);

	if (wget_tcp_get_stats_dns(WGET_STATS_DNS_PORT, stats))
		dns_stats.port = *((uint16_t *)wget_tcp_get_stats_dns(WGET_STATS_DNS_PORT, stats));

	if (wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats))
		dns_stats.millisecs = *((long long *)wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats));

	wget_thread_mutex_lock(stats_dns_opts.mutex);
	wget_vector_add(stats_dns_opts.data, &dns_stats, sizeof(dns_stats_t));
	wget_thread_mutex_unlock(stats_dns_opts.mutex);
}

static void free_dns_stats(dns_stats_t *stats)
{
	if (stats) {
		xfree(stats->host);
		xfree(stats->ip);
	}
}

static void stats_print_human_dns_entry(struct json_stats *ctx, const dns_stats_t *dns_stats)
{
	fprintf(ctx->fp, "  %4lld %s:%hu (%s)\n",
		dns_stats->millisecs,
		dns_stats->host,
		dns_stats->port,
		dns_stats->ip);
}

static void stats_print_csv_dns_entry(struct json_stats *ctx, const dns_stats_t *dns_stats)
{
	fprintf(ctx->fp, "%s,%s,%hu,%lld\n",
		dns_stats->host,
		dns_stats->ip,
		dns_stats->port,
		dns_stats->millisecs);
}

static void stats_print_json_dns_entry(struct json_stats *ctx, const dns_stats_t *dns_stats)
{
	static char tabs[] = "\t\t\t\t\t\t\t\t\t\t";

	fprintf(ctx->fp, "%.*s{\n", ctx->ntabs + 1, tabs);
	fprintf(ctx->fp, "%.*s\"Hostname\" : \"%s\",\n", ctx->ntabs + 2, tabs, dns_stats->host);
	fprintf(ctx->fp, "%.*s\"IP\" : \"%s\",\n", ctx->ntabs + 2, tabs, dns_stats->ip);
	fprintf(ctx->fp, "%.*s\"Port\" : %hu,\n", ctx->ntabs + 2, tabs, dns_stats->port);
	fprintf(ctx->fp, "%.*s\"Duration\" : %lld\n", ctx->ntabs + 2, tabs, dns_stats->millisecs);
	if (ctx->last)
		fprintf(ctx->fp, "%.*s}\n", ctx->ntabs + 1, tabs);
	else
		fprintf(ctx->fp, "%.*s},\n", ctx->ntabs + 1, tabs);
}

static void stats_print_dns_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nDNS Timings:\n");
	fprintf(fp, "  %4s %s\n", "ms", "Host");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_human_dns_entry, fp, 0);
}

static void stats_print_dns_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,IP,Port,Duration\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_csv_dns_entry, fp, 0);
}

static void stats_print_dns_json(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\t\"DNS Timings\": [{\n");
	stats_print_data(opts->data, (wget_vector_browse_t) stats_print_json_dns_entry, fp, 0);
	fprintf(fp, "\t}]\n");
}

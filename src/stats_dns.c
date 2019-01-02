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
 * DNS statistics functions
 *
 */
#include <config.h>

#include <wget.h>
#include <stdio.h>
#include <stdint.h>

#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"

typedef struct {
	const char
		*host,
		*ip;
	long long
		millisecs;
	uint16_t
		port;
} dns_stats_t;

// Forward declarations for static functions
static void print_human(stats_opts_t *opts, FILE *fp);
static void print_csv(stats_opts_t *opts, FILE *fp);
static void stats_callback(const void *stats);
static void free_stats(dns_stats_t *stats);

static stats_print_func_t
	print_dns[] = {
		[WGET_STATS_FORMAT_HUMAN] = print_human,
		[WGET_STATS_FORMAT_CSV] = print_csv,
	};

stats_opts_t stats_dns_opts = {
	.tag = "DNS",
	.options = &config.stats_dns,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_dns,
	.callback = stats_callback,
	.destructor = (wget_vector_destructor_t) free_stats,
	.print = print_dns,
};

static void stats_callback(const void *stats)
{
	dns_stats_t dns_stats = { .millisecs = -1, .port = -1 };

	dns_stats.host = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_HOST, stats));
	dns_stats.ip = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_IP, stats));

	if (wget_tcp_get_stats_dns(WGET_STATS_DNS_PORT, stats))
		dns_stats.port = *((uint16_t *)wget_tcp_get_stats_dns(WGET_STATS_DNS_PORT, stats));

	if (wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats))
		dns_stats.millisecs = *((long long *)wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats));

	wget_thread_mutex_lock(stats_dns_opts.mutex);
	wget_vector_add(stats_dns_opts.data, &dns_stats, sizeof(dns_stats_t));
	wget_thread_mutex_unlock(stats_dns_opts.mutex);
}

static void free_stats(dns_stats_t *stats)
{
	if (stats) {
		xfree(stats->host);
		xfree(stats->ip);
	}
}

static int print_human_entry(FILE *fp, const dns_stats_t *dns_stats)
{
	fprintf(fp, "  %4lld %s:%hu (%s)\n",
		dns_stats->millisecs,
		NULL_TO_DASH(dns_stats->host),
		dns_stats->port,
		NULL_TO_DASH(dns_stats->ip));

	return 0;
}

static int print_csv_entry(FILE *fp, const dns_stats_t *dns_stats)
{
	fprintf(fp, "%s,%s,%hu,%lld\n",
		dns_stats->host ? dns_stats->host : "",
		dns_stats->ip ? dns_stats->ip : "",
		dns_stats->port,
		dns_stats->millisecs);

	return 0;
}

static void print_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nDNS Timings:\n");
	fprintf(fp, "  %4s %s\n", "ms", "Host");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_human_entry, fp);
}

static void print_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,IP,Port,Duration\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_csv_entry, fp);
}

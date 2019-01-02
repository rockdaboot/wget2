/*
 * Copyright(c) 2017-2019 Free Software Foundation, Inc.
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
 * Server statistics functions
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
		*hostname,
		*ip;
	char
		scheme,
		hsts,
		csp,
		hpkp_new;
	wget_hpkp_stats_t
		hpkp;
} server_stats_t;

// Forward declarations for static functions
static void print_human(stats_opts_t *opts, FILE *fp);
static void print_csv(stats_opts_t *opts, FILE *fp);
static void stats_callback(const void *stats);
static void free_stats(server_stats_t *stats);

static stats_print_func_t
	print_server[] = {
		[WGET_STATS_FORMAT_HUMAN] = print_human,
		[WGET_STATS_FORMAT_CSV] = print_csv,
	};

stats_opts_t stats_server_opts = {
	.tag = "Server",
	.options = &config.stats_server,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_server,
	.callback = stats_callback,
	.destructor = (wget_vector_destructor_t) free_stats,
	.print = print_server,
};

static void stats_callback(const void *stats)
{
	server_stats_t server_stats = { .hpkp_new = -1, .hsts = -1, .csp = -1, .hpkp = WGET_STATS_HPKP_NO };

	server_stats.hostname = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_HOSTNAME, stats));
	server_stats.ip = wget_strdup(wget_tcp_get_stats_server(WGET_STATS_SERVER_IP, stats));

	const char *scheme = wget_tcp_get_stats_server(WGET_STATS_SERVER_SCHEME, stats);
	if (scheme) {
		if (!strcmp(scheme, "http"))
			server_stats.scheme = 1;
		else if (!strcmp(scheme, "https"))
			server_stats.scheme = 2;
	}

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

static void free_stats(server_stats_t *stats)
{
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->ip);
	}
}

G_GNUC_WGET_PURE static const char *_hpkp_string(wget_hpkp_stats_t hpkp)
{
	switch (hpkp) {
	case WGET_STATS_HPKP_NO: return "HPKP_NO";
	case WGET_STATS_HPKP_MATCH: return "HPKP_MATCH";
	case WGET_STATS_HPKP_NOMATCH: return "HPKP_NOMATCH";
	case WGET_STATS_HPKP_ERROR: return "HPKP_ERROR";
	default: return "?";
	}
}

G_GNUC_WGET_PURE static const char *_scheme_string(int scheme)
{
	switch (scheme) {
	case 1: return "http";
	case 2: return "https";
	default: return "?";
	}
}

static int print_human_entry(FILE *fp, const server_stats_t *server_stats)
{
	fprintf(fp, "  %s:\n", NULL_TO_DASH(server_stats->hostname));
	fprintf(fp, "    IP             : %s\n", NULL_TO_DASH(server_stats->ip));
	fprintf(fp, "    Scheme         : %s\n", _scheme_string(server_stats->scheme));
	fprintf(fp, "    HPKP           : %s\n", _hpkp_string(server_stats->hpkp));
	fprintf(fp, "    HPKP New Entry : %s\n", ON_OFF_DASH(server_stats->hpkp_new));
	fprintf(fp, "    HSTS           : %s\n", ON_OFF_DASH(server_stats->hsts));
	fprintf(fp, "    CSP            : %s\n\n", ON_OFF_DASH(server_stats->csp));

	return 0;
}

static int print_csv_entry(FILE *fp, const server_stats_t *server_stats)
{
	fprintf(fp, "%s,%s,%d,%d,%d,%d,%d\n",
		server_stats->hostname ? server_stats->hostname : "",
		server_stats->ip ? server_stats->ip : "",
		server_stats->scheme,
		(int) server_stats->hpkp,
		server_stats->hpkp_new,
		server_stats->hsts,
		server_stats->csp);

	return 0;
}

static void print_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nServer Statistics:\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_human_entry, fp);
}

static void print_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,IP,Scheme,HPKP,NewHPKP,HSTS,CSP\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_csv_entry, fp);
}

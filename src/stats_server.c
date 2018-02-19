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
		*ip,
		*scheme;
	char
		hsts,
		csp,
		hpkp_new;
	wget_hpkp_stats_t
		hpkp;
} server_stats_t;

// Forward declarations for static functions
static void print_human(stats_opts_t *opts, FILE *fp);
static void print_csv(stats_opts_t *opts, FILE *fp);
static void print_json(stats_opts_t *opts, FILE *fp);
static void stats_callback(const void *stats);
static void free_stats(server_stats_t *stats);

static stats_print_func_t
	print_server[] = {
		[WGET_STATS_FORMAT_HUMAN] = print_human,
		[WGET_STATS_FORMAT_CSV] = print_csv,
		[WGET_STATS_FORMAT_JSON] = print_json,
	};

stats_opts_t stats_server_opts = {
	.tag = "Server",
	.options = &config.stats_server,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_server,
	.callback = stats_callback,
	.destructor = (wget_vector_destructor_t) free_stats,
	.print = print_server,
};

static char tabs[] = "\t\t\t\t\t\t\t\t\t\t";

static void stats_callback(const void *stats)
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

static void free_stats(server_stats_t *stats)
{
	if (stats) {
		xfree(stats->hostname);
		xfree(stats->ip);
		xfree(stats->scheme);
	}
}

G_GNUC_WGET_PURE static const char *stats_hpkp(wget_hpkp_stats_t hpkp)
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

static void print_human_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	fprintf(ctx->fp, "  %s:\n", server_stats->hostname);
	fprintf(ctx->fp, "    IP             : %s\n", server_stats->ip);
	fprintf(ctx->fp, "    Scheme         : %s\n", server_stats->scheme);
	fprintf(ctx->fp, "    HPKP           : %s\n", stats_hpkp(server_stats->hpkp));
	fprintf(ctx->fp, "    HPKP New Entry : %s\n", ON_OFF_DASH(server_stats->hpkp_new));
	fprintf(ctx->fp, "    HSTS           : %s\n", ON_OFF_DASH(server_stats->hsts));
	fprintf(ctx->fp, "    CSP            : %s\n\n", ON_OFF_DASH(server_stats->csp));
}

static void print_json_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	fprintf(ctx->fp, "%.*s{\n", ctx->ntabs + 1, tabs);
	fprintf(ctx->fp, "%.*s\"Hostname\" : \"%s\",\n", ctx->ntabs + 2, tabs, server_stats->hostname);
	fprintf(ctx->fp, "%.*s\"IP\" : \"%s\",\n", ctx->ntabs + 2, tabs, server_stats->ip);
	fprintf(ctx->fp, "%.*s\"Scheme\" : \"%s\",\n", ctx->ntabs + 2, tabs, HTTP_S_DASH(server_stats->scheme));
	fprintf(ctx->fp, "%.*s\"HPKP\" : \"%s\",\n", ctx->ntabs + 2, tabs, stats_hpkp(server_stats->hpkp));
	fprintf(ctx->fp, "%.*s\"NewHPKP\" : \"%s\",\n", ctx->ntabs + 2, tabs, ON_OFF_DASH(server_stats->hpkp_new));
	fprintf(ctx->fp, "%.*s\"HSTS\" : \"%s\",\n", ctx->ntabs + 2, tabs, ON_OFF_DASH(server_stats->hsts));
	fprintf(ctx->fp, "%.*s\"CSP\" : \"%s\"\n", ctx->ntabs + 2, tabs, ON_OFF_DASH(server_stats->csp));
	if (ctx->last)
		fprintf(ctx->fp, "%.*s}\n", ctx->ntabs + 1, tabs);
	else
		fprintf(ctx->fp, "%.*s},\n", ctx->ntabs + 1, tabs);
}

static void print_csv_entry(struct json_stats *ctx, const server_stats_t *server_stats)
{
	fprintf(ctx->fp, "%s,%s,%s,%s,%s,%s,%s\n",
		server_stats->hostname,
		server_stats->ip,
		HTTP_S_DASH(server_stats->scheme),
		stats_hpkp(server_stats->hpkp),
		ONE_ZERO_DASH(server_stats->hpkp_new),
		ONE_ZERO_DASH(server_stats->hsts),
		ONE_ZERO_DASH(server_stats->csp));
}

static void print_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nServer Statistics:\n");
	stats_print_data(opts->data, (wget_vector_browse_t) print_human_entry, fp, 0);
}

static void print_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,IP,Scheme,HPKP,NewHPKP,HSTS,CSP\n");
	stats_print_data(opts->data, (wget_vector_browse_t) print_csv_entry, fp, 0);
}

static void print_json(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\t\"Server Statistics\": [{\n");
	stats_print_data(opts->data, (wget_vector_browse_t) print_json_entry, fp, 0);
	fprintf(fp, "\t}]\n");
}

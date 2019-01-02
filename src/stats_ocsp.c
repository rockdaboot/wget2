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
 * OCSP statistics functions
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
		*hostname;
	int
		nvalid,
		nrevoked,
		nignored,
		stapling;
} ocsp_stats_t;

// Forward declarations for static functions
static void print_human(stats_opts_t *opts, FILE *fp);
static void print_csv(stats_opts_t *opts, FILE *fp);
static void stats_callback(const void *stats);
static void free_stats(ocsp_stats_t *stats);

static stats_print_func_t
	print_ocsp[] = {
		[WGET_STATS_FORMAT_HUMAN] = print_human,
		[WGET_STATS_FORMAT_CSV] = print_csv,
	};

stats_opts_t stats_ocsp_opts = {
	.tag = "OCSP",
	.options = &config.stats_ocsp,
	.set_callback = (stats_callback_setter_t) wget_tcp_set_stats_ocsp,
	.callback = stats_callback,
	.destructor = (wget_vector_destructor_t) free_stats,
	.print = print_ocsp,
};

static void stats_callback(const void *stats)
{
	ocsp_stats_t ocsp_stats = { .nvalid = -1, .nrevoked = -1, .nignored = -1 };

	ocsp_stats.hostname = wget_strdup(wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_HOSTNAME, stats));

	if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats))
		ocsp_stats.nvalid = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_VALID, stats));

	if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats))
		ocsp_stats.nrevoked = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_REVOKED, stats));

	if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats))
		ocsp_stats.nignored = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_IGNORED, stats));

	if (wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_STAPLING, stats))
		ocsp_stats.stapling = *((int *)wget_tcp_get_stats_ocsp(WGET_STATS_OCSP_STAPLING, stats));

	wget_thread_mutex_lock(stats_ocsp_opts.mutex);
	wget_vector_add(stats_ocsp_opts.data, &ocsp_stats, sizeof(ocsp_stats_t));
	wget_thread_mutex_unlock(stats_ocsp_opts.mutex);
}

static void free_stats(ocsp_stats_t *stats)
{
	if (stats)
		xfree(stats->hostname);
}

static int print_human_entry(FILE *fp, const ocsp_stats_t *ocsp_stats)
{
	fprintf(fp, "  %s:\n", ocsp_stats->hostname);
	fprintf(fp, "    Stapling       : %d\n", ocsp_stats->stapling);
	fprintf(fp, "    Valid          : %d\n", ocsp_stats->nvalid);
	fprintf(fp, "    Revoked        : %d\n", ocsp_stats->nrevoked);
	fprintf(fp, "    Ignored        : %d\n\n", ocsp_stats->nignored);

	return 0;
}

static int print_csv_entry(FILE *fp, const ocsp_stats_t *ocsp_stats)
{
	fprintf(fp, "%s,%d,%d,%d,%d\n",
		ocsp_stats->hostname,
		ocsp_stats->stapling,
		ocsp_stats->nvalid,
		ocsp_stats->nrevoked,
		ocsp_stats->nignored);

	return 0;
}

static void print_human(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "\nOCSP Statistics:\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_human_entry, fp);
}

static void print_csv(stats_opts_t *opts, FILE *fp)
{
	fprintf(fp, "Hostname,Stapling,Valid,Revoked,Ignored\n");
	wget_vector_browse(opts->data, (wget_vector_browse_t) print_csv_entry, fp);
}

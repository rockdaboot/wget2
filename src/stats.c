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

extern stats_print_func_t
	print_dns[],
	print_ocsp[],
	print_server[],
	print_site,
	print_tls[];

static stats_opts_t *stats_opts[] = {
	[WGET_STATS_TYPE_DNS] = &stats_dns_opts,
	[WGET_STATS_TYPE_OCSP] = &stats_ocsp_opts,
	[WGET_STATS_TYPE_SERVER] = &stats_server_opts,
	[WGET_STATS_TYPE_SITE] = &stats_site_opts,
	[WGET_STATS_TYPE_TLS] = &stats_tls_opts,
};

static int stats_parse_options(const char *val, wget_stats_format_t *format, const char **filename)
{
	const char *p = val;

	if ((p = strchr(val, ':'))) {
		if (!wget_strncasecmp_ascii("human", val, p - val) || !wget_strncasecmp_ascii("h", val, p - val))
			*format = WGET_STATS_FORMAT_HUMAN;
		else if (!wget_strncasecmp_ascii("csv", val, p - val))
			*format = WGET_STATS_FORMAT_CSV;
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
			xfree(opts->file);
			return -1;
		}

		wget_thread_mutex_init(&opts->mutex);

		opts->data = wget_vector_create(8, NULL);
		wget_vector_set_destructor(opts->data, opts->destructor);
		opts->set_callback(opts->callback);
	}

	return 0;
}

void stats_exit(void)
{
	for (unsigned it = 0; it < countof(stats_opts); it++) {
		stats_opts_t *opts = stats_opts[it];

		if (!opts->mutex)
			continue;

		wget_vector_free(&opts->data);
		wget_thread_mutex_destroy(&opts->mutex);
		xfree(opts->file);
	}
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
			info_printf(_("%s stats saved in %s\n"), opts->tag, filename);
			fclose(fp);
		}
	}
}

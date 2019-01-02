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

#ifndef SRC_WGET_STATS_H
#define SRC_WGET_STATS_H

#include <stdio.h>
#include <stdbool.h>

#include "wget_host.h"
#include "wget_gpgme.h"

#define NULL_TO_DASH(s) ((s) ? (s) : "-")
#define ONE_ZERO_DASH(s) ((s) ? ((s) == 1 ? "1" : "-") : "0")
#define ON_OFF_DASH(s) ((s) ? ((s) == 1 ? "On" : "-") : "Off")
#define YES_NO(s) ((s) ? "Yes" : "No")
#define HTTP_1_2(s) ((s) == WGET_PROTOCOL_HTTP_1_1 ? "HTTP/1.1" : ((s) == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"))
#define HTTP_S_DASH(s) (strcmp(s, "http") ? (strcmp(s, "https") ? s : "1") : "0")

typedef struct stats_opts stats_opts_t;
typedef void (*stats_print_func_t)(stats_opts_t *, FILE *);
typedef void (*stats_callback_setter_t)(wget_stats_callback_t);

struct stats_opts {
	const char
		**options,
		*tag,
		*file;
	wget_stats_format_t
		format;
	wget_vector_t
		*data;
	wget_thread_mutex_t
		mutex;
	stats_callback_setter_t
		set_callback;
	wget_stats_callback_t
		callback;
	wget_vector_destructor_t
		destructor;
	stats_print_func_t
		*print;
};

extern stats_opts_t stats_dns_opts;
extern stats_opts_t stats_ocsp_opts;
extern stats_opts_t stats_server_opts;
extern stats_opts_t stats_tls_opts;
extern stats_opts_t stats_site_opts;

int stats_init(void);
void stats_exit(void);
void stats_print(void);
void stats_site_add(wget_http_response_t *resp, wget_gpg_info_t *gpg_info);

#endif /* SRC_WGET_STATS_H */

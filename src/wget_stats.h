/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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

#include "wget_gpgme.h"

#define NULL_TO_DASH(s) ((s) ? (s) : "-")
#define ON_OFF_DASH(s) ((s) ? ((s) == 1 ? "On" : "-") : "Off")
#define YES_NO(s) ((s) ? "Yes" : "No")
#define HTTP_1_2(s) ((s) == WGET_PROTOCOL_HTTP_1_1 ? "HTTP/1.1" : ((s) == WGET_PROTOCOL_HTTP_2_0 ? "HTTP/2" : "-"))

void site_stats_print(void);
void stats_site_add(wget_http_response *resp, wget_gpg_info_t *gpg_info);
void site_stats_init(FILE *fp);
void site_stats_exit(void);

void server_stats_init(FILE *fp);
void server_stats_exit(void);

#endif /* SRC_WGET_STATS_H */

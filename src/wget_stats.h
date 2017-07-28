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

#ifndef _WGET_STATS_H
#define _WGET_STATS_H

typedef struct {
	const char
		*host,
		*ip;
	long long
		millisecs;
} dns_stats_t;

typedef struct {
	const char
		*hostname,
		*version,
		*false_start,
		*tfo,
		*alpn_proto;
	char
		tls_con,
		resumed,
		tcp_protocol;
	int cert_chain_size;
	long long millisecs;
} tls_stats_t;

typedef struct {
	const char
	*hostname,
	*ip,
	*hsts,
	*csp,
	*hpkp_new;

	char
		hpkp;
} server_stats_t;

typedef struct {
	const char
		*hostname;
	int
		nvalid,
		nrevoked,
		nignored;
} ocsp_stats_t;

void stats_init(void);
void stats_print(void);

#endif

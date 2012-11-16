/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for option routines
 *
 * Changelog
 * 12.06.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_OPTIONS_H
#define _MGET_OPTIONS_H

#include <stdarg.h>

#include "mget.h"

struct config {
	const char
		*directory_prefix,
		*http_proxy,
		*https_proxy,
		*cookie_suffixes,
		*load_cookies,
		*save_cookies,
		*logfile,
		*logfile_append,
		*user_agent,
		*output_document,
		*ca_cert,
		*ca_directory,
		*cert_file,
		*egd_file,
		*private_key,
		*random_file,
		*secure_protocol; // auto, SSLv2, SSLv3, TLSv1
	int
		preferred_family,
		cut_directories,
		connect_timeout, // ms
		dns_timeout, // ms
		read_timeout, // ms
		max_redirect,
		num_threads;
	char
		cache,
		inet4_only,
		inet6_only,
		delete_after,
		strict_comments,
		protocol_directories,
		host_directories,
		force_directories,
		directories,
		timestamping,
		use_server_timestamps,
		continue_download,
		server_response,
		keep_alive,
		keep_session_cookies,
		cookies,
		spider,
		dns_caching,
		check_certificate,
		cert_type, // SSL_X509_FMT_PEM or SSL_X509_FMT_DER (=ASN1)
		private_key_type, // SSL_X509_FMT_PEM or SSL_X509_FMT_DER (=ASN1)
		span_hosts,
		recursive,
		verbose,
		quiet,
		debug;
};

extern struct config
	config;

int
	init(int argc, const char *const *argv) NONNULL_ALL,
	selftest_options(void);
void
	deinit(void);

#endif /* _MGET_OPTIONS_H */

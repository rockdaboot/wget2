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

#include <libmget.h>

// types fro --restrict-file-names
#define RESTRICT_NAMES_NONE  1<<0
#define RESTRICT_NAMES_UNIX  1<<1
#define RESTRICT_NAMES_WINDOWS  1<<2
#define RESTRICT_NAMES_NOCONTROL  1<<3
#define RESTRICT_NAMES_ASCII  1<<4
#define RESTRICT_NAMES_UPPERCASE  1<<5
#define RESTRICT_NAMES_LOWERCASE  1<<6

struct config {
	MGET_IRI
		*base;
	const char
		*username,
		*password,
		*http_username,
		*http_password,
		*local_encoding,
		*remote_encoding,
		*bind_address,
		*input_file,
		*base_url,
		*default_page,
		*referer,
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
	MGET_STRINGMAP
		*domains,
		*exclude_domains;
	size_t
		chunk_size;
	long long
		quota;
	int
		restrict_file_names,
		level,
		preferred_family,
		cut_directories,
		connect_timeout, // ms
		dns_timeout, // ms
		read_timeout, // ms
		max_redirect,
		num_threads;
	char
		trust_server_names,
		robots,
		parent,
		https_only,
		content_disposition,
		page_requisites,
		force_css,
		force_html,
		adjust_extension,
		save_headers,
		clobber,
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
		check_hostname,
		cert_type, // SSL_X509_FMT_PEM or SSL_X509_FMT_DER (=ASN1)
		private_key_type, // SSL_X509_FMT_PEM or SSL_X509_FMT_DER (=ASN1)
		span_hosts,
		recursive,
		verbose,
		print_version,
		quiet,
		debug;
};

extern struct config
	config;

int
	init(int argc, const char *const *argv) G_GNUC_MGET_NONNULL_ALL,
	selftest_options(void);
void
	deinit(void);

#endif /* _MGET_OPTIONS_H */

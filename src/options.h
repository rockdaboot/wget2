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

// types for --restrict-file-names
#define RESTRICT_NAMES_NONE  0
#define RESTRICT_NAMES_UNIX  1<<0
#define RESTRICT_NAMES_WINDOWS  1<<1
#define RESTRICT_NAMES_NOCONTROL  1<<2
#define RESTRICT_NAMES_ASCII  1<<3
#define RESTRICT_NAMES_UPPERCASE  1<<4
#define RESTRICT_NAMES_LOWERCASE  1<<5

struct config {
	mget_iri_t
		*base;
	const char
		*post_file,
		*post_data,
		*progress,
		*gnutls_options,
		*username,
		*password,
		*http_username,
		*http_password,
		*input_encoding, // encoding of files given with --input-file (or -i) (if not specified in the document itself)
		*local_encoding,  // encoding of the environment and file system
		*remote_encoding, // encoding of remote files (if not specified in Content-Type HTTP header or in document itself)
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
		*hsts_file,
		*ocsp_file,
		*logfile,
		*logfile_append,
		*user_agent,
		*output_document,
		*ca_cert,
		*ca_directory,
		*cert_file,
		*crl_file,
		*egd_file,
		*private_key,
		*random_file,
		*secure_protocol; // auto, SSLv2, SSLv3, TLSv1
	mget_vector_t
		*domains,
		*exclude_domains,
		*accept_patterns,
		*reject_patterns,
		*follow_tags,
		*ignore_tags;
	mget_hsts_db_t
		*hsts_db; // in-memory HSTS database
	mget_ocsp_db_t
		*ocsp_db; // in-memory fingerprint OCSP database
	size_t
		chunk_size;
	long long
		quota;
	int
		backups,
		tries,
		wait,
		waitretry,
		restrict_file_names,
		level,
		preferred_family,
		cut_directories,
		connect_timeout, // ms
		dns_timeout, // ms
		read_timeout, // ms
		max_redirect,
		num_threads;
	struct mget_cookie_db_st
		*cookie_db;
	char
		http2,
		ocsp_stapling,
		ocsp,
		mirror,
		backup_converted,
		convert_links,
		ignore_case,
		hsts, // if HSTS (HTTP Strict Transport Security) is enabled or not
		random_wait,
		trust_server_names,
		robots,
		parent,
		https_only,
		content_disposition,
		page_requisites,
		force_rss,
		force_atom,
		force_sitemap,
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
		tcp_fastopen,
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

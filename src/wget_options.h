/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * Header file for option routines
 *
 * Changelog
 * 12.06.2012  Tim Ruehsen  created
 *
 */

#ifndef _WGET_OPTIONS_H
#define _WGET_OPTIONS_H

#include <stdarg.h>

#include <wget.h>

struct config {
	wget_iri_t
		*base;
	const char
		*post_file,
		*post_data,
		*gnutls_options,
		*username,
		*password,
		*http_username,
		*http_password,
		*http_proxy_username,
		*http_proxy_password,
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
		*no_proxy,
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
		*crl_file,
		*egd_file,
		*private_key,
		*random_file,
		*secure_protocol; // auto, SSLv2, SSLv3, TLSv1
	wget_vector_t
		*config_files,
		*domains,
		*exclude_domains,
		*accept_patterns,
		*reject_patterns,
		*follow_tags,
		*ignore_tags,
		*default_challenges,
		*headers;
	wget_hsts_db_t
		*hsts_db; // in-memory HSTS database
	wget_hpkp_db_t
		*hpkp_db; // in-memory HPKP database
	wget_tls_session_db_t
		*tls_session_db; // in-memory TLS session database
	wget_ocsp_db_t
		*ocsp_db; // in-memory fingerprint OCSP database
	wget_netrc_db_t
		*netrc_db; // in-memory .netrc database
	struct _wget_cookie_db_st
		*cookie_db;
	char
		*hsts_file,
		*hpkp_file,
		*tls_session_file,
		*ocsp_file,
		*netrc_file;
	size_t
		chunk_size;
	long long
		quota;
	bool
		auth_no_challenge;
	int
		http2_request_window,
		http1_request_window,
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
		max_threads;
	char
		tls_resume,            // if TLS session resumption is enabled or not
		tls_false_start,
		progress,
		content_on_error,
		fsync_policy,
		netrc,
		http2,
		ocsp_stapling,
		ocsp,
		mirror,
		backup_converted,
		convert_links,
		ignore_case,
		hsts,                  // if HSTS (HTTP Strict Transport Security) is enabled or not
		hpkp,                  // HTTP Public Key Pinning (HPKP)
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
		force_metalink,
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
		cert_type,             // SSL_X509_FMT_PEM or SSL_X509_FMT_DER (=ASN1)
		private_key_type,      // SSL_X509_FMT_PEM or SSL_X509_FMT_DER (=ASN1)
		span_hosts,
		recursive,
		verbose,
		print_version,
		quiet,
		debug,
		metalink,
		cut_url_get_vars,
		cut_file_get_vars,
		proxy,
		xattr,
		force_progress,
		stats_dns,
		stats_tls;
};

extern struct config
	config;

int init(int argc, const char **argv) G_GNUC_WGET_NONNULL_ALL;
int selftest_options(void);
void deinit(void);

#endif /* _WGET_OPTIONS_H */

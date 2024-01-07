/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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

#ifndef SRC_WGET_OPTIONS_H
#define SRC_WGET_OPTIONS_H

#include <stdarg.h>
#include <unistd.h> // needed for EXIT_SUCCESS

#ifdef WITH_LIBHSTS
#include <libhsts.h>
#endif

#include <wget.h>

#define INCLUDED_DIRECTORY_PREFIX '+'
#define EXCLUDED_DIRECTORY_PREFIX '-'

typedef enum {
	CHECK_CERTIFICATE_ENABLED,
	CHECK_CERTIFICATE_DISABLED,
	// certificate error/warning log is enabled in the other modes
	CHECK_CERTIFICATE_LOG_DISABLED
} check_certificate_mode;

//types for --https-enforce
typedef enum {
	HTTPS_ENFORCE_NONE,
	HTTPS_ENFORCE_SOFT,
	HTTPS_ENFORCE_HARD
} https_enforce_mode;

typedef enum {
	GPG_VERIFY_DISABLED,
	GPG_VERIFY_SIG_FAIL,
	WGET_GPG_VERIFY_SIG_NO_FAIL
} gpg_verify_mode;

typedef enum {
	DOWNLOAD_ATTR_NO,
	DOWNLOAD_ATTR_STRIPPATH,
	DOWNLOAD_ATTR_USEPATH,
} download_attr_mode;

typedef struct {
	const char
		*filename;
	FILE
		*fp;
	wget_stats_format
		format;
} stats_args;

struct config {
	wget_iri
		*base;
	const char
		*post_file,
		*post_data,
		*body_file,
		*body_data,
		*http_username,
		*http_password,
		*http_proxy_username,
		*http_proxy_password,
		*input_encoding, // encoding of files given with --input-file (or -i) (if not specified in the document itself)
		*local_encoding,  // encoding of the environment and file system
		*remote_encoding, // encoding of remote files (if not specified in Content-Type HTTP header or in document itself)
		*bind_address,
		*bind_interface,
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
		*secure_protocol, // auto, SSLv2, SSLv3, TLSv1
		*accept_regex,
		*reject_regex,
		*gnupg_homedir,
		*stats_all,
		*system_config,
		*user_config,
		*hsts_file,
		*hsts_preload_file,
		*hpkp_file,
		*tls_session_file,
		*ocsp_server,
		*ocsp_file,
		*netrc_file,
		*use_askpass_bin,
		*hostname,
		*dns_cache_preload,
		*method;
	wget_vector
		*compression,
		*domains,
		*exclude_directories,
		*exclude_domains,
		*accept_patterns,
		*reject_patterns,
#ifdef WITH_GPGME
		*sig_ext,
#endif
		*follow_tags,
		*ignore_tags,
		*default_challenges,
		*headers,
		*mime_types,
		*retry_on_http_error,
		*save_content_on;
	wget_content_encoding
		compression_methods[wget_content_encoding_max + 1];	// the last one for counting
	wget_hsts_db
		*hsts_db; // in-memory HSTS database
#ifdef WITH_LIBHSTS
	hsts_t
		*hsts_preload_data; // in-memory HSTS preloaded data
#endif
	wget_hpkp_db
		*hpkp_db; // in-memory HPKP database
	wget_tls_session_db
		*tls_session_db; // in-memory TLS session database
	wget_ocsp_db
		*ocsp_db; // in-memory fingerprint OCSP database
	wget_netrc_db
		*netrc_db; // in-memory .netrc database
	wget_cookie_db
		*cookie_db;
	stats_args
		*stats_dns_args,
		*stats_ocsp_args,
		*stats_server_args,
		*stats_site_args,
		*stats_tls_args;
	char
		*password,
		*username;
	size_t
		chunk_size;
	long long
		quota,
		limit_rate, // bytes
		start_pos; // bytes
	int
		http2_request_window,
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
	uint16_t
		default_http_port,
		default_https_port;
	wget_report_speed
		report_speed;
	check_certificate_mode
		check_certificate;
	https_enforce_mode
		https_enforce;
	gpg_verify_mode
		verify_sig;
	char
		cert_type,             // SSL_X509_FMT_PEM or SSL_X509_FMT_DER (=ASN1)
		private_key_type,      // SSL_X509_FMT_PEM or SSL_X509_FMT_DER (=ASN1)
		progress,
		regex_type,
		download_attr;
	bool
		tls_resume,            // if TLS session resumption is enabled or not
		content_on_error,
		fsync_policy,
		netrc,
		http2,
		http2_only,
		ocsp_stapling,
		ocsp,
		mirror,
		backup_converted,
		convert_file_only,
		convert_links,
		ignore_case,
		ignore_length,
		hsts,                  // if HSTS (HTTP Strict Transport Security) is enabled or not
		hsts_preload,          // if loading of a HSTS Preload file is enabled of not
		hpkp,                  // HTTP Public Key Pinning (HPKP)
		random_wait,
		trust_server_names,
		robots,
		parent,
		https_only,
		content_disposition,
		page_requisites,
		follow_sitemaps,
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
		keep_extension,
		keep_session_cookies,
		cookies,
		spider,
		dns_caching,
		check_hostname,
		span_hosts,
		verbose,
		quiet,
		debug,
		hyperlink,
		metalink,
		cut_url_get_vars,
		cut_file_get_vars,
		proxy,
		xattr,
		force_progress,
		local_db,
		dont_write, // fuzzers and unit/fuzz tests set this to 1, so they won't write any files
		filter_urls,
		askpass,
		verify_save_failed,
		retry_connrefused,
		unlink,
		background,
		if_modified_since,
		auth_no_challenge,
		no_compression,
		ocsp_date,
		ocsp_nonce,
		recursive,
		tls_false_start,
		tcp_fastopen,
		dane;
};

extern struct config
	config;

typedef enum {
	EXIT_STATUS_NO_ERROR       = EXIT_SUCCESS,
	EXIT_STATUS_GENERIC        = 1,
	EXIT_STATUS_PARSE_INIT     = 2,
	EXIT_STATUS_IO             = 3,
	EXIT_STATUS_NETWORK        = 4,
	EXIT_STATUS_TLS            = 5,
	EXIT_STATUS_AUTH           = 6,
	EXIT_STATUS_PROTOCOL       = 7,
	EXIT_STATUS_REMOTE         = 8,
	EXIT_STATUS_GPG_ERROR      = 9
} exit_status_e;

// Needed for fuzzers that are compiled by C++
#ifdef __cplusplus
extern "C" {
#endif

int init(int argc, const char **argv) WGET_GCC_NONNULL_ALL;
int selftest_options(void);
void deinit(void);
void set_exit_status(exit_status_e status);
exit_status_e get_exit_status(void);

#ifdef __cplusplus
}
#endif

#endif /* SRC_WGET_OPTIONS_H */

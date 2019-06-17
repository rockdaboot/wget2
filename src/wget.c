/*
 * Copyright(c) 2012-2014 Tim Ruehsen
 * Copyright(c) 2015-2019 Free Software Foundation, Inc.
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
 * Main file
 *
 * Changelog
 * 07.04.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <c-ctype.h>
#include <ctype.h>
#include <time.h>
#include <fnmatch.h>
#include <regex.h>
#include <sys/stat.h>
#include <locale.h>

#ifdef _WIN32
#include <windows.h> // GetFileAttributes()
#endif

#if defined __clang__
  // silence warnings in gnulib code
  #pragma clang diagnostic ignored "-Wshorten-64-to-32"
#endif

#include "timespec.h" // gnulib gettime()
#include "safe-read.h"
#include "safe-write.h"

#ifdef WITH_LIBPCRE2
# define PCRE2_CODE_UNIT_WIDTH 8
# include <pcre2.h>
#elif defined WITH_LIBPCRE
# include <pcre.h>
# ifndef PCRE_STUDY_JIT_COMPILE
#  define PCRE_STUDY_JIT_COMPILE 0
# endif
#endif

#include "wget_main.h"
#include "wget_log.h"
#include "wget_job.h"
#include "wget_options.h"
#include "wget_blacklist.h"
#include "wget_host.h"
#include "wget_bar.h"
#include "wget_xattr.h"
#include "wget_dl.h"
#include "wget_plugin.h"
#include "wget_stats.h"
#include "wget_testing.h"
#include "wget_utils.h"

#ifdef WITH_GPGME
#  include "wget_gpgme.h"
#endif

// flags for add_url()
#define URL_FLG_REDIRECTION     (1<<0)
#define URL_FLG_SITEMAP         (1<<1)
#define URL_FLG_SKIPFALLBACK    (1<<2)
#define URL_FLG_REQUISITE       (1<<3)
#define URL_FLG_SIGNATURE_REQ   (1<<4)
#define URL_FLG_NO_BLACKLISTING (1<<5)

#define _CONTENT_TYPE_HTML 1
typedef struct {
	const char *
		filename;
	const char *
		encoding;
	wget_iri_t *
		base_url;
	wget_html_parsed_result_t *
		parsed;
	int
		content_type;
} _conversion_t;
static wget_vector_t *conversions;

typedef struct {
	int
		ndownloads; // file downloads with 200 response
	int
		nredirects; // 301, 302
	int
		nnotmodified; // 304
	int
		nerrors;
	int
		nchunks; // chunk downloads with 200 response
	long long
		bytes_body_uncompressed; // uncompressed bytes in body
} _statistics_t;
static _statistics_t stats;

static int G_GNUC_WGET_NONNULL((1)) _prepare_file(wget_http_response_t *resp, const char *fname, int flag,
		wget_iri_t *uri, wget_iri_t *original_url, int ignore_patterns, wget_buffer_t *partial_content,
		size_t max_partial_content, char **actual_file_name, const char *path);

static void
	sitemap_parse_xml(JOB *job, const char *data, const char *encoding, wget_iri_t *base),
	sitemap_parse_xml_gz(JOB *job, wget_buffer_t *data, const char *encoding, wget_iri_t *base),
	sitemap_parse_xml_localfile(JOB *job, const char *fname, const char *encoding, wget_iri_t *base),
	sitemap_parse_text(JOB *job, const char *data, const char *encoding, wget_iri_t *base),
	atom_parse(JOB *job, const char *data, const char *encoding, wget_iri_t *base),
	atom_parse_localfile(JOB *job, const char *fname, const char *encoding, wget_iri_t *base),
	rss_parse(JOB *job, const char *data, const char *encoding, wget_iri_t *base),
	rss_parse_localfile(JOB *job, const char *fname, const char *encoding, wget_iri_t *base),
	metalink_parse_localfile(const char *fname),
	html_parse(JOB *job, int level, const char *data, size_t len, const char *encoding, wget_iri_t *base),
	html_parse_localfile(JOB *job, int level, const char *fname, const char *encoding, wget_iri_t *base),
	css_parse(JOB *job, const char *data, size_t len, const char *encoding, wget_iri_t *base),
	css_parse_localfile(JOB *job, const char *fname, const char *encoding, wget_iri_t *base);
static unsigned int G_GNUC_WGET_PURE
	hash_url(const char *url);
static int
	read_xattr_metadata(const char *name, char *value, size_t size, int fd),
	write_xattr_metadata(const char *name, const char *value, int fd),
	write_xattr_last_modified(time_t last_modified, int fd),
	set_file_metadata(wget_iri_t *origin_url, wget_iri_t *referrer_url, const char *mime_type, const char *charset, time_t last_modified, FILE *fp),
	http_send_request(wget_iri_t *iri, wget_iri_t *original_url, DOWNLOADER *downloader);
wget_http_response_t
	*http_receive_response(wget_http_connection_t *conn);
static long long G_GNUC_WGET_NONNULL_ALL get_file_size(const char *fname);

static wget_stringmap_t
	*etags;
static wget_hashmap_t
	*known_urls;
static DOWNLOADER
	*downloaders;
static void
	*downloader_thread(void *p);
static wget_thread_mutex_t
	quota_mutex;
static long long
	quota;
static int
	hsts_changed,
	hpkp_changed;
static volatile bool
	terminate;
static int
	nthreads;

// generate the local filename corresponding to an URI
// respect the following options:
// --restrict-file-names (unix,windows,nocontrol,ascii,lowercase,uppercase)
// -nd / --no-directories
// -x / --force-directories
// -nH / --no-host-directories
// --protocol-directories
// --cut-dirs=number
// -P / --directory-prefix=prefix

static const char * G_GNUC_WGET_NONNULL_ALL _get_local_filename(const wget_iri_t *iri)
{
	wget_buffer_t buf;
	char *fname;
	int directories;

	directories = !!config.recursive;

	if (config.directories == 0)
		directories = 0;

	if (config.force_directories == 1)
		directories = 1;

	wget_buffer_init(&buf, NULL, 256);

	if (config.directory_prefix && *config.directory_prefix) {
		wget_buffer_strcat(&buf, config.directory_prefix);
		wget_buffer_memcat(&buf, "/", 1);
	}

	if (directories) {
		if (config.protocol_directories && iri->scheme && *iri->scheme) {
			wget_buffer_strcat(&buf, iri->scheme);
			wget_buffer_memcat(&buf, "/", 1);
		}

		if (config.host_directories && iri->host && *iri->host) {
			wget_buffer_strcat(&buf, iri->host);
			wget_buffer_memcat(&buf, "/", 1);
		}

		if (config.cut_directories) {
			// cut directories
			wget_buffer_t path_buf;
			const char *p;
			int n;
			char sbuf[256];

			wget_buffer_init(&path_buf, sbuf, sizeof(sbuf));
			wget_iri_get_path(iri, &path_buf, config.local_encoding);

			for (n = 0, p = path_buf.data; n < config.cut_directories && p; n++) {
				p = strchr(*p == '/' ? p + 1 : p, '/');
			}

			if (!p && path_buf.data) {
				// we can't strip this many path elements, just use the filename
				p = strrchr(path_buf.data, '/');
				if (!p)
					p = path_buf.data;
			}

			if (p) {
				while (*p == '/')
					p++;

				wget_buffer_strcat(&buf, p);
			}

			wget_buffer_deinit(&path_buf);
		} else {
			wget_iri_get_path(iri, &buf, config.local_encoding);
		}

		if (config.cut_file_get_vars)
			fname = buf.data;
		else
			fname = wget_iri_get_query_as_filename(iri, &buf, config.local_encoding);
	} else {
		if (config.cut_file_get_vars)
			fname = wget_iri_get_path(iri, &buf, config.local_encoding);
		else
			fname = wget_iri_get_filename(iri, &buf, config.local_encoding);
	}

	// do the filename escaping here
	if (config.restrict_file_names) {
		char fname_esc[buf.length * 3 + 1];

		if (wget_restrict_file_name(fname, fname_esc, config.restrict_file_names) != fname) {
			// escaping was really done, replace fname
			wget_buffer_strcpy(&buf, fname_esc);
			fname = buf.data;
		}
	}

	// create the complete directory path
//	mkdir_path(fname);

	debug_printf("local filename = '%s'\n", fname);

	return fname;
}

const char * G_GNUC_WGET_NONNULL_ALL get_local_filename(const wget_iri_t *iri)
{
	if (config.delete_after)
		return NULL;

	if ((config.spider || config.output_document) && !config.continue_download)
		return NULL;

	return _get_local_filename(iri);
}

static long long _fetch_and_add_longlong(long long *p, long long n)
{
#ifdef WITH_SYNC_FETCH_AND_ADD_LONGLONG
	return __sync_fetch_and_add(p, n);
#else
	wget_thread_mutex_lock(quota_mutex);
	long long old_value = *p;
	*p += n;
	wget_thread_mutex_unlock(quota_mutex);

	return old_value;
#endif
}

static void _atomic_increment_int(int *p)
{
#ifdef WITH_SYNC_FETCH_AND_ADD
	__sync_fetch_and_add(p, 1);
#else
	wget_thread_mutex_lock(quota_mutex);
	*p += 1;
	wget_thread_mutex_unlock(quota_mutex);
#endif
}

// Since quota may change at any time in a threaded environment,
// we have to modify and check the quota in one (protected) step.
static long long quota_modify_read(size_t nbytes)
{
	return _fetch_and_add_longlong(&quota, (long long)nbytes);
}

static void nop(int sig)
{
	if (sig == SIGTERM) {
		abort(); // hard stop if got a SIGTERM
	} else if (sig == SIGINT) {
		if (terminate)
			abort(); // hard stop if pressed CTRL-C a second time

		terminate = 1; // set global termination flag
		wget_http_abort_connection(NULL); // soft-abort all connections
#ifdef SIGWINCH
	} else if (sig == SIGWINCH) {
		wget_bar_screen_resized();
#endif
	}
}

static void
	*input_thread(void *p);
static wget_thread_t
	input_tid;
static wget_vector_t
	*parents;
static wget_thread_mutex_t
	downloader_mutex,
	main_mutex,
	known_urls_mutex,
	etag_mutex,
	savefile_mutex,
	netrc_mutex,
	conversion_mutex;

static wget_thread_cond_t
	main_cond,   // is signaled whenever a job is done
	worker_cond; // is signaled whenever a job is added

static void _wget_init(void)
{
	wget_global_init(0);
	blacklist_init();
	host_init();

	wget_thread_mutex_init(&downloader_mutex);
	wget_thread_mutex_init(&main_mutex);
	wget_thread_mutex_init(&known_urls_mutex);
	wget_thread_mutex_init(&etag_mutex);
	wget_thread_mutex_init(&savefile_mutex);
	wget_thread_mutex_init(&netrc_mutex);
	wget_thread_mutex_init(&conversion_mutex);
	wget_thread_mutex_init(&quota_mutex);
	wget_thread_cond_init(&main_cond);
	wget_thread_cond_init(&worker_cond);

	setlocale(LC_ALL, "");

#ifdef ENABLE_NLS
	bindtextdomain("wget", LOCALEDIR);
	textdomain("wget");
#endif

#ifdef _WIN32
	// not sure if this is needed for Windows
	// signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, nop);
	signal(SIGINT, nop);
#else
	// need to set some signals
	struct sigaction sig_action;
	memset(&sig_action, 0, sizeof(sig_action));

	sig_action.sa_sigaction = (void (*)(int, siginfo_t *, void *))SIG_IGN;
	sigaction(SIGPIPE, &sig_action, NULL); // this forces socket error return
	sig_action.sa_handler = nop;
	sigaction(SIGTERM, &sig_action, NULL);
	sigaction(SIGINT, &sig_action, NULL);
	sigaction(SIGWINCH, &sig_action, NULL);
#endif

	known_urls = wget_hashmap_create(128, (wget_hashmap_hash_t)hash_url, (wget_hashmap_compare_t)strcmp);

	// Initialize the plugin system
	plugin_db_init();
#ifdef WGET_PLUGIN_DIR
	plugin_db_add_search_paths(WGET_PLUGIN_DIR, 0);
#endif
}

static void _wget_deinit(void)
{
	host_exit();
	blacklist_exit();

	wget_thread_mutex_destroy(&downloader_mutex);
	wget_thread_mutex_destroy(&main_mutex);
	wget_thread_mutex_destroy(&known_urls_mutex);
	wget_thread_mutex_destroy(&etag_mutex);
	wget_thread_mutex_destroy(&savefile_mutex);
	wget_thread_mutex_destroy(&netrc_mutex);
	wget_thread_mutex_destroy(&conversion_mutex);
	wget_thread_mutex_destroy(&quota_mutex);
	wget_thread_cond_destroy(&main_cond);
	wget_thread_cond_destroy(&worker_cond);
}

/* Check if 'subdir' is a subdirectory of 'dir'.
 * E.g. if 'dir' is `/something', match_subdir() will return true if and
 * only if 'subdir' begins with `/something/' or is exactly '/something'.
 */
static bool match_subdir(const char *dir, const char *subdir, char ignore_case)
{
	if (*dir == '\0')
		return (strcmp(subdir, "/")) ? false : true;

	if (ignore_case)
		for (; *dir && *subdir && (c_tolower(*dir) == c_tolower(*subdir)); ++dir, ++subdir)
			;
	else
		while (*dir && *subdir && (*dir++ == *subdir++))
			;

	return *dir == 0 && (*subdir == 0 || *subdir == '/');
}

static int in_directory_pattern_list(const wget_vector_t *v, const char *fname)
{
	// if -I was given: exclude all be default
	// if -X was given alone: include all be default
	const char *pattern;
	char *path;
	bool default_exclude = 0;

	if (*fname == '/')
		fname++;

	const char *e = strrchr(fname, '/');
	if (!e)
		//return default_exclude; // no path component found
		path = wget_strdup("/");
	else
		path = wget_strmemdup(fname, e - fname);

	pattern = wget_vector_get(v, 0);
	default_exclude = (*pattern == INCLUDED_DIRECTORY_PREFIX);

	for (int it = wget_vector_size(v) - 1; it >= 0; it--) {
		pattern = wget_vector_get(v, it);

		bool exclude = (*pattern != INCLUDED_DIRECTORY_PREFIX);

		pattern++;

		if (*pattern == '/')
			pattern++;

		debug_printf("directory[%d] '%s' - '%s' %c\n", it, pattern, path, "+-"[exclude]);

		if (strpbrk(pattern, "*?[]")) {
			// path="/we/all/love/wget" wouldn't match "/*/all/*" but "/*/all/*/*"
			if (!fnmatch(pattern, path, FNM_PATHNAME | (config.ignore_case ? FNM_CASEFOLD : 0))) {
				wget_free(path);
				return exclude;
			}
		} else if (match_subdir(pattern, path, config.ignore_case)) {
			// path="/we/all/love/wget" would match "/we/all/"
			wget_free(path);
			return exclude;
		}
	}

	wget_free(path);

	return default_exclude;
}

static int in_pattern_list(const wget_vector_t *v, const char *url)
{
	for (int it = 0; it < wget_vector_size(v); it++) {
		const char *pattern = wget_vector_get(v, it);

		debug_printf("pattern[%d] '%s' - %s\n", it, pattern, url);

		if (strpbrk(pattern, "*?[]")) {
			if (!fnmatch(pattern, url, config.ignore_case ? FNM_CASEFOLD : 0))
				return 1;
		} else if (config.ignore_case) {
			if (wget_match_tail_nocase(url, pattern))
				return 1;
		} else if (wget_match_tail(url, pattern)) {
			return 1;
		}
	}

	return 0;
}

static int in_host_pattern_list(const wget_vector_t *v, const char *hostname)
{
	for (int it = 0; it < wget_vector_size(v); it++) {
		const char *pattern = wget_vector_get(v, it);

		debug_printf("host_pattern[%d] '%s' - %s\n", it, pattern, hostname);

		if (strpbrk(pattern, "*?[]")) {
			if (!fnmatch(pattern, hostname, 0))
				return 1;
		} else if (wget_match_tail(pattern, hostname)) {
			return 1;
		}
	}

	return 0;
}

static int regex_match_posix(const char *string, const char *pattern)
{
	int	status;
	regex_t	re;

	if (regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0)
		return 0;

	status = regexec(&re, string, (size_t) 0, NULL, 0);

	regfree(&re);

	if (status != 0)
		return 0;

	return 1;
}

#ifdef WITH_LIBPCRE2
static int regex_match_pcre(const char *string, const char *pattern)
{
	pcre2_code *re;
	int errornumber;
	PCRE2_SIZE erroroffset;
	pcre2_match_data *match_data;
	int rc, result = 0;

	re = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
	if (re == NULL)
		return 0;

	match_data = pcre2_match_data_create_from_pattern(re, NULL);

	rc = pcre2_match(re, (PCRE2_SPTR) string, strlen(string), 0, 0, match_data, NULL);
	if (rc >= 0)
		result = 1;

	pcre2_match_data_free(match_data);
	pcre2_code_free(re);

	return result;
}
#elif defined WITH_LIBPCRE
static int regex_match_pcre(const char *string, const char *pattern)
{
	pcre *re;
	pcre_extra *extra;
	const char *error_msg;
	int error;
	int offsets[8];
	int rc, result = 0;

	re = pcre_compile(pattern, 0, &error_msg, &error, NULL);
	if (re == NULL)
		return 0;

	error_msg = NULL;
	extra = pcre_study(re, 0, &error_msg);
	if (error_msg != NULL) {
		pcre_free(re);
		return 0;
	}

	rc = pcre_exec(re, extra, string, (int) strlen(string), 0, 0, offsets, 8);
	if (rc >= 0)
		result = 1;

	if (extra != NULL)
#ifdef PCRE_CONFIG_JIT
		pcre_free_study(extra);
#else
		pcre_free(extra);
#endif

	pcre_free(re);

	return result;
}
#endif

static int regex_match(const char *string, const char *pattern)
{
#if defined WITH_LIBPCRE2 || defined WITH_LIBPCRE
	if (config.regex_type == WGET_REGEX_TYPE_PCRE)
		return regex_match_pcre(string, pattern);
	else
		return regex_match_posix(string, pattern);
#else
	return regex_match_posix(string, pattern);
#endif
}

static void parse_localfile(JOB *job, const char *fname, const char *encoding, const char *mimetype, wget_iri_t *base)
{
	int fd;
	int level = job ? job->level : 0;
	char _mimetype[64], _encoding[32];

	if ((fd = open(fname, O_RDONLY)) == -1)
		return;

	if (!mimetype) {
		if (read_xattr_metadata("user.mimetype", _mimetype, sizeof(_mimetype), fd) < 0)
			*_mimetype = 0;
		else if (*_mimetype)
			mimetype = _mimetype;
	}

	if (!encoding) {
		if (read_xattr_metadata("user.charset", _encoding, sizeof(_encoding), fd) < 0)
			*_encoding = 0;
		else if (*_encoding)
			encoding = _encoding;
	}

	close(fd);

	if (mimetype) {
		if (!wget_strcasecmp_ascii(mimetype, "text/html") || !wget_strcasecmp_ascii(mimetype, "application/xhtml+xml")) {
			html_parse_localfile(job, level, fname, encoding, base);
		} else if (!wget_strcasecmp_ascii(mimetype, "text/css")) {
			css_parse_localfile(job, fname, encoding, base);
		} else if (!wget_strcasecmp_ascii(mimetype, "text/xml") || !wget_strcasecmp_ascii(mimetype, "application/xml")) {
			sitemap_parse_xml_localfile(job, fname, encoding ? encoding : "utf-8", base);
		} else if (!wget_strcasecmp_ascii(mimetype, "application/atom+xml")) {
			atom_parse_localfile(job, fname, encoding ? encoding : "utf-8", base);
		} else if (!wget_strcasecmp_ascii(mimetype, "application/rss+xml")) {
			rss_parse_localfile(job, fname, encoding ? encoding : "utf-8", base);
		}
	} else {
		const char *ext = strrchr(fname, '.');

		if (ext) {
			if (!wget_strcasecmp_ascii(ext, ".html") || !wget_strcasecmp_ascii(ext, ".htm")) {
				html_parse_localfile(job, level, fname, encoding, base);
			} else if (!wget_strcasecmp_ascii(ext, ".css")) {
				css_parse_localfile(job, fname, encoding, base);
			} else if (!wget_strcasecmp_ascii(ext, ".rss")) {
				rss_parse_localfile(job, fname, encoding ? encoding : "utf-8", base);
			}
		}
	}
}

// Add URLs given by user (command line, file or -i option).
// Needs to be thread-save.
static void add_url_to_queue(const char *url, wget_iri_t *base, const char *encoding, int flags)
{
	wget_iri_t *iri;
	JOB *new_job = NULL, job_buf;
	HOST *host;
	const char *local_filename;
	struct plugin_db_forward_url_verdict plugin_verdict;
	bool http_fallback = 0;

	iri = wget_iri_parse_base(base, url, encoding);

	if (!iri) {
		error_printf(_("Failed to parse URI '%s'\n"), url);
		return;
	}

	// Allow plugins to intercept URLs
	plugin_db_forward_url(iri, &plugin_verdict);
	if (plugin_verdict.reject) {
		wget_iri_free(&iri);
		plugin_db_forward_url_verdict_free(&plugin_verdict);
		return;
	}
	if (plugin_verdict.alt_iri) {
		wget_iri_free(&iri);
		iri = plugin_verdict.alt_iri;
		plugin_verdict.alt_iri = NULL;
	}

	if (iri->scheme != WGET_IRI_SCHEME_HTTP && iri->scheme != WGET_IRI_SCHEME_HTTPS) {
		error_printf(_("URI scheme not supported: '%s'\n"), url);
		wget_iri_free(&iri);
		plugin_db_forward_url_verdict_free(&plugin_verdict);
		return;
	}

	wget_thread_mutex_lock(downloader_mutex);

	if (iri->scheme == WGET_IRI_SCHEME_HTTP && config.https_enforce) {
		wget_iri_set_scheme(iri, WGET_IRI_SCHEME_HTTPS);
		if (config.https_enforce == WGET_HTTPS_ENFORCE_SOFT)
			http_fallback = 1;
	}

	if (!blacklist_add(iri)) {
		if (!(flags & URL_FLG_NO_BLACKLISTING)) {
			// we know this URL already
			wget_thread_mutex_unlock(downloader_mutex);
			plugin_db_forward_url_verdict_free(&plugin_verdict);
			return;
		}
	}

	// only download content from hosts given on the command line or from input file
	if (wget_vector_contains(config.exclude_domains, iri->host)) {
		// download from this scheme://domain are explicitly not wanted
		debug_printf("not requesting '%s'. (Exclude Domains)\n", iri->uri);
		wget_thread_mutex_unlock(downloader_mutex);
		plugin_db_forward_url_verdict_free(&plugin_verdict);
		return;
	}

	if (plugin_verdict.alt_local_filename) {
		local_filename = plugin_verdict.alt_local_filename;
		plugin_verdict.alt_local_filename = NULL;
	} else {
		local_filename = get_local_filename(iri);
	}

	if (!config.clobber && local_filename && access(local_filename, F_OK) == 0) {
		debug_printf("not requesting '%s'. (File already exists)\n", iri->uri);
		wget_thread_mutex_unlock(downloader_mutex);
		if (config.recursive || config.page_requisites) {
			parse_localfile(NULL, local_filename, NULL, NULL, iri);
		}
		xfree(local_filename);
		plugin_db_forward_url_verdict_free(&plugin_verdict);
		return;
	}

	if ((host = host_add(iri))) {
		// a new host entry has been created
		if (config.recursive && config.robots) {
			if (!config.clobber && local_filename && access(local_filename, F_OK) == 0) {
				debug_printf("not requesting '%s'. (File already exists)\n", iri->uri);
			} else {
				// create a special job for downloading robots.txt (before anything else)
				wget_iri_t *robot_iri = wget_iri_parse_base(iri, "/robots.txt", encoding);

				if (blacklist_add(robot_iri))
					host_add_robotstxt_job(host, robot_iri, http_fallback);
			}
		}
	} else
		host = host_get(iri);

	if (config.recursive) {
		if (!config.span_hosts) {
			if (wget_vector_find(config.domains, iri->host) == -1)
				wget_vector_add_str(config.domains, iri->host);
		}

		if (!config.parent) {
			char *p;

			if (!parents)
				parents = wget_vector_create(4, NULL);

			// calc length of directory part in iri->path (including last /)
			if (!iri->path || !(p = strrchr(iri->path, '/')))
				iri->dirlen = 0;
			else
				iri->dirlen = p - iri->path + 1;

			wget_vector_add_noalloc(parents, iri);
		}
	}

	new_job = job_init(&job_buf, iri, http_fallback);
	new_job->local_filename = local_filename;

	if (plugin_verdict.accept) {
		new_job->ignore_patterns = 1;
	} else if (config.mime_types) {
		new_job->head_first = 1; // enable mime-type check to assure e.g. text/html to be downloaded and parsed
	} else if (config.recursive) {
		if ((config.accept_patterns && !in_pattern_list(config.accept_patterns, new_job->iri->uri))
				|| (config.accept_regex && !regex_match(new_job->iri->uri, config.accept_regex)))
			new_job->head_first = 1; // enable mime-type check to assure e.g. text/html to be downloaded and parsed

		if ((config.reject_patterns && in_pattern_list(config.reject_patterns, new_job->iri->uri))
				|| (config.reject_regex && regex_match(new_job->iri->uri, config.reject_regex)))
			new_job->head_first = 1; // enable mime-type check to assure e.g. text/html to be downloaded and parsed
	}

	if (config.recursive)
		new_job->requested_by_user = 1; // download even if disallowed by robots.txt

	if (config.spider || config.chunk_size)
		new_job->head_first = 1;

	if (config.auth_no_challenge) {
		new_job->challenges = config.default_challenges;
		new_job->challenges_alloc = false;
	}

	host_add_job(host, new_job);

	wget_thread_mutex_unlock(downloader_mutex);

	plugin_db_forward_url_verdict_free(&plugin_verdict);
}

// Add URLs parsed from downloaded files
// Needs to be thread-safe
static void add_url(JOB *job, const char *encoding, const char *url, int flags)
{
	JOB *new_job = NULL, job_buf;
	wget_iri_t *iri;
	HOST *host;
	const char *local_filename = NULL;
	struct plugin_db_forward_url_verdict plugin_verdict;
	bool http_fallback = 0;

	if (flags & URL_FLG_REDIRECTION) { // redirect
		if (job && job->redirection_level >= config.max_redirect) {
			debug_printf("not requesting '%s'. (Max Redirections exceeded)\n", url);
			return;
		}
	}

	wget_info_printf(_("Adding URL: %s\n"), url);

	const char *p = NULL;

	if (config.cut_url_get_vars)
		p = strchr(url, '?');

	if (p) {
		char *url_cut = wget_strmemdup(url, p - url);
		iri = wget_iri_parse(url_cut, encoding);
		xfree(url_cut);
	}
	else
		iri = wget_iri_parse(url, encoding);

	if (!iri) {
		error_printf(_("Cannot resolve URI '%s'\n"), url);
		return;
	}

	// Allow plugins to intercept URL
	plugin_db_forward_url(iri, &plugin_verdict);

	if (plugin_verdict.reject) {
		debug_printf("not requesting '%s'. (Plugin Verdict)\n", url);
		plugin_db_forward_url_verdict_free(&plugin_verdict);
		wget_iri_free(&iri);
		return;
	}

	if (plugin_verdict.alt_iri) {
		debug_printf("Plugin changed IRI. %s -> %s\n", iri->uri, plugin_verdict.alt_iri->uri);
		wget_iri_free(&iri);
		iri = plugin_verdict.alt_iri;
		plugin_verdict.alt_iri = NULL;
	}

	if (iri->scheme != WGET_IRI_SCHEME_HTTP && iri->scheme != WGET_IRI_SCHEME_HTTPS) {
		info_printf(_("URL '%s' not followed (unsupported scheme '%s')\n"), url, iri->scheme);
		wget_iri_free(&iri);
		plugin_db_forward_url_verdict_free(&plugin_verdict);
		return;
	}

	if (config.https_only && iri->scheme != WGET_IRI_SCHEME_HTTPS) {
		info_printf(_("URL '%s' not followed (https-only requested)\n"), url);
		wget_iri_free(&iri);
		plugin_db_forward_url_verdict_free(&plugin_verdict);
		return;
	}

	if (iri->scheme == WGET_IRI_SCHEME_HTTP && config.https_enforce && !(flags & URL_FLG_SKIPFALLBACK)) {
		wget_iri_set_scheme(iri, WGET_IRI_SCHEME_HTTPS);
		if (config.https_enforce == WGET_HTTPS_ENFORCE_SOFT)
			http_fallback = 1;
	}

	wget_thread_mutex_lock(downloader_mutex);

	if (!blacklist_add(iri)) {
		// we know this URL already
		// iri has been free'd by blacklist_add()
		goto out;
	}

	if (config.recursive) {
		// only download content from given hosts
		const char *reason = NULL;

		if (!iri->host)
			reason = _("missing ip/host/domain");
		else if (job && strcmp(job->iri->host, iri->host)) {
			if (!config.span_hosts && !in_host_pattern_list(config.domains, iri->host))
				reason = _("no host-spanning requested");
			else if (config.span_hosts && in_host_pattern_list(config.exclude_domains, iri->host))
				reason = _("domain explicitly excluded");
		}

		if (reason) {
			info_printf(_("URL '%s' not followed (%s)\n"), iri->uri, reason);
			goto out;
		}
	}

	if (config.recursive && !config.parent && !(flags & URL_FLG_REQUISITE)) {
		// do not ascend above the parent directory
		bool ok = false;

		// see if at least one parent matches
		for (int it = 0; it < wget_vector_size(parents); it++) {
			wget_iri_t *parent = wget_vector_get(parents, it);

			if (!wget_strcmp(parent->host, iri->host)) {
				if (!parent->dirlen || !wget_strncmp(parent->path, iri->path, parent->dirlen)) {
					// info_printf("found\n");
					ok = true;
					break;
				}
			}
		}

		if (!ok) {
			info_printf(_("URL '%s' not followed (parent ascending not allowed)\n"), url);
			goto out;
		}
	}

	if (!config.output_document) {
		if (plugin_verdict.alt_local_filename) {
			local_filename = plugin_verdict.alt_local_filename;
			plugin_verdict.alt_local_filename = NULL;
		} else if (!(flags & URL_FLG_REDIRECTION) || config.trust_server_names || !job) {
			local_filename = get_local_filename(iri);
		} else {
			local_filename = wget_strdup(job->local_filename);
		}

		if (!config.clobber && local_filename && access(local_filename, F_OK) == 0) {
			info_printf(_("URL '%s' not requested (file already exists)\n"), iri->uri);
			wget_thread_mutex_unlock(downloader_mutex);
			if (config.recursive && (!config.level || (job && job->level < config.level + config.page_requisites))) {
				parse_localfile(job, local_filename, encoding, NULL, iri);
			}
			// do not 'goto out;' here
			xfree(local_filename);
			plugin_db_forward_url_verdict_free(&plugin_verdict);
			return;
		}
	}

	if ((host = host_add(iri))) {
		// a new host entry has been created
		if (config.recursive && config.robots) {
			if (!config.clobber && local_filename && access(local_filename, F_OK) == 0) {
				debug_printf("not requesting '%s' (File already exists)\n", iri->uri);
			} else {
				// create a special job for downloading robots.txt (before anything else)
				wget_iri_t *robot_iri = wget_iri_parse_base(iri, "/robots.txt", encoding);

				if (blacklist_add(robot_iri))
					host_add_robotstxt_job(host, robot_iri, http_fallback);
			}
		}
	} else if ((host = host_get(iri))) {
		if (host->robots && iri->path) {
			// info_printf("%s: checking '%s' / '%s'\n", __func__, iri->path, iri->uri);
			for (int it = 0, n = wget_robots_get_path_count(host->robots); it < n; it++) {
				wget_string_t *path = wget_robots_get_path(host->robots, it);
				// info_printf("%s: checked robot path '%.*s' / '%s' / '%s'\n", __func__, (int)path->len, path->path, iri->path, iri->uri);
				if (path->len && !strncmp(path->p + 1, iri->path ? iri->path : "", path->len - 1)) {
					info_printf(_("URL '%s' not followed (disallowed by robots.txt)\n"), iri->uri);
					goto out;
				}
			}
		}
	} else {
		// this should really not ever happen
		error_printf(_("Failed to get '%s' from hosts\n"), iri->host);
		goto out;
	}

	if (config.recursive && config.filter_urls) {
		if ((config.accept_patterns && !in_pattern_list(config.accept_patterns, iri->uri))
			|| (config.accept_regex && !regex_match(iri->uri, config.accept_regex)))
		{
			debug_printf("not requesting '%s'. (doesn't match accept pattern)\n", iri->uri);
			goto out;
		}

		if ((config.reject_patterns && in_pattern_list(config.reject_patterns, iri->uri))
			|| (config.reject_regex && regex_match(iri->uri, config.reject_regex)))
		{
			debug_printf("not requesting '%s'. (matches reject pattern)\n", iri->uri);
			goto out;
		}

		if (config.exclude_directories && in_directory_pattern_list(config.exclude_directories, iri->path)) {
			debug_printf("not requesting '%s' (path excluded)\n", iri->uri);
			goto out;
		}
	}

	new_job = job_init(&job_buf, iri, http_fallback);
	new_job->local_filename = local_filename;
	local_filename = NULL;

	if (job) {
		if (flags & URL_FLG_REDIRECTION) {
			new_job->parent_id = job->parent_id;
			new_job->level = job->level;
			new_job->redirection_level = job->redirection_level + 1;
			new_job->referer = job->referer;
			new_job->original_url = job->iri;
		} else {
			new_job->parent_id = job->id;
			new_job->level = job->level + 1;
			new_job->referer = job->iri;
			if (flags & URL_FLG_SIGNATURE_REQ) {
				if (job->sig_req) {
					// A chained signature request needs to have the same verifying file uri
					new_job->sig_req = wget_strdup(job->sig_req);
					new_job->level = job->level; // Chained signature requests shouldn't count towards level
				} else {
					new_job->sig_req = wget_strdup(job->iri->uri);
				}
				new_job->sig_filename = wget_strdup(job->sig_filename);
				if (job->remaining_sig_ext) {
					new_job->remaining_sig_ext = job->remaining_sig_ext;
					job->remaining_sig_ext = NULL;
				}
			}
		}
	}

	if (plugin_verdict.accept) {
		new_job->ignore_patterns = 1;
	} else if (config.mime_types) {
		new_job->head_first = 1; // enable mime-type check to assure e.g. text/html to be downloaded and parsed
	} else if (config.recursive) {
		if ((config.accept_patterns && !in_pattern_list(config.accept_patterns, new_job->iri->uri))
				|| (config.accept_regex && !regex_match(new_job->iri->uri, config.accept_regex)))
			new_job->head_first = 1; // enable mime-type check to assure e.g. text/html to be downloaded and parsed

		if ((config.reject_patterns && in_pattern_list(config.reject_patterns, new_job->iri->uri))
				|| (config.reject_regex && regex_match(new_job->iri->uri, config.reject_regex)))
			new_job->head_first = 1; // enable mime-type check to assure e.g. text/html to be downloaded and parsed

		if (config.exclude_directories && in_directory_pattern_list(config.exclude_directories, new_job->iri->path))
			new_job->head_first = 1; // enable mime-type check to assure e.g. text/html to be downloaded and parsed
	}

	if (config.spider || config.chunk_size)
		new_job->head_first = 1;

	if (config.auth_no_challenge)
		new_job->challenges = config.default_challenges;

	// mark this job as a Sitemap job, but not if it is a robot.txt job
	if (flags & URL_FLG_SITEMAP)
		new_job->sitemap = 1;

	// now add the new job to the queue (thread-safe))
	host_add_job(host, new_job);

	// and wake up all waiting threads
	wget_thread_cond_signal(worker_cond);

out:
	xfree(local_filename);
	wget_thread_mutex_unlock(downloader_mutex);
	plugin_db_forward_url_verdict_free(&plugin_verdict);
}

static void _convert_links(void)
{
	FILE *fpout = NULL;
	wget_buffer_t buf;
	char sbuf[1024];

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	// cycle through all documents where links have been found
	for (int it = 0; it < wget_vector_size(conversions); it++) {
		_conversion_t *conversion = wget_vector_get(conversions, it);
		const char *data, *data_ptr;
		size_t data_length;

		wget_info_printf(_("convert %s %s %s\n"), conversion->filename, conversion->base_url->uri, conversion->encoding);

		if (!(data = data_ptr = wget_read_file(conversion->filename, &data_length))) {
			wget_error_printf(_("%s not found (%d)\n"), conversion->filename, errno);
			continue;
		}

		// cycle through all links found in the document
		for (int it2 = 0; it2 < wget_vector_size(conversion->parsed->uris); it2++) {
			wget_html_parsed_url_t *html_url = wget_vector_get(conversion->parsed->uris, it2);
			wget_string_t *url = &html_url->url;

			url->p = (size_t) url->p + data; // convert offset to pointer

			if (url->len >= 1 && *url->p == '#') // ignore e.g. href='#'
				continue;

			if (wget_iri_relative_to_abs(conversion->base_url, url->p, url->len, &buf)) {
				// buf.data now holds the absolute URL as a string
				wget_iri_t *iri = wget_iri_parse(buf.data, conversion->encoding);

				if (!iri) {
					wget_error_printf(_("Cannot resolve URI '%s'\n"), buf.data);
					continue;
				}

				const char *filename = get_local_filename(iri);

				if (access(filename, W_OK) == 0) {
					const char *linkpath = filename, *dir = NULL, *p1, *p2;
					const char *docpath = conversion->filename;

					// e.g.
					// docpath  'hostname/1level/2level/3level/xyz.html'
					// linkpath 'hostname/1level/2level.bak/3level/xyz.html'
					// expected result: '../../2level.bak/3level/xyz.html'

					// find first difference in path
					for (dir = p1 = linkpath, p2 = docpath; *p1 && *p1 == *p2; p1++, p2++)
						if (*p1 == '/') dir = p1+1;

					// generate relative path
					wget_buffer_reset(&buf); // reuse buffer
					while (*p2) {
						if (*p2++ == '/')
							wget_buffer_memcat(&buf, "../", 3);
					}
					wget_buffer_strcat(&buf, dir);

					wget_info_printf("  %.*s -> %s\n", (int) url->len,  url->p, linkpath);
					wget_info_printf("       -> %s\n", buf.data);
				} else {
					// insert absolute URL
					wget_info_printf("  %.*s -> %s\n", (int) url->len,  url->p, buf.data);
				}

				if (buf.length != url->len || strncmp(buf.data, url->p, url->len)) {
					// conversion takes place, write to disk
					if (!fpout) {
						if (config.backup_converted) {
							char dstfile[strlen(conversion->filename) + 5 + 1];

							wget_snprintf(dstfile, sizeof(dstfile), "%s.orig", conversion->filename);

							if (rename(conversion->filename, dstfile) == -1) {
								wget_error_printf(_("Failed to rename %s to %s (%d)"), conversion->filename, dstfile, errno);
							}
						}
						if (!(fpout = fopen(conversion->filename, "wb")))
							wget_error_printf(_("Failed to write open %s (%d)"), conversion->filename, errno);
					}
					if (fpout) {
						fwrite(data_ptr, 1, url->p - data_ptr, fpout);
						fwrite(buf.data, 1, buf.length, fpout);
						data_ptr = url->p + url->len;
					}
				}
				xfree(filename);
				wget_iri_free(&iri);
			}
		}

		if (fpout) {
			fwrite(data_ptr, 1, (data + data_length) - data_ptr, fpout);
			fclose(fpout);
			fpout = NULL;
		}

		xfree(data);
	}

	wget_buffer_deinit(&buf);
}

static void print_status(DOWNLOADER *downloader, const char *fmt, ...) G_GNUC_WGET_NONNULL_ALL G_GNUC_WGET_PRINTF_FORMAT(2,3);
static void print_status(DOWNLOADER *downloader G_GNUC_WGET_UNUSED, const char *fmt, ...)
{
	if (config.verbose) {
		va_list args;

		va_start(args, fmt);
		wget_info_vprintf(fmt, args);
		va_end(args);
	}
}

static void print_progress_report(long long start_time)
{

	if (config.progress) {
		char quota_buf[16];
		char speed_buf[16];
		char rs_type = (config.report_speed == WGET_REPORT_SPEED_BYTES) ? 'B' : 'b';
		long long tdiff = wget_get_timemillis() - start_time;
		if (!tdiff) tdiff = 1;
		// The time is in milliseconds, so upscale
		unsigned int mod = 1000 * ((config.report_speed == WGET_REPORT_SPEED_BYTES) ? 1 : 8);

		if (config.spider)
			bar_printf(nthreads, "Headers: %d (%d redirects & %d errors) Bytes: %s [%s%c/s] Todo: %d",
				stats.nerrors+stats.ndownloads+stats.nredirects+stats.nnotmodified,
				stats.nredirects, stats.nerrors,
				wget_human_readable(quota_buf, sizeof(quota_buf), quota),
				wget_human_readable(speed_buf, sizeof(speed_buf), (quota*mod)/tdiff), rs_type,
				queue_size()
			);
		else
			bar_printf(nthreads, "Files: %d  Bytes: %s [%s%c/s] Redirects: %d  Todo: %d  Errors: %d",
				stats.ndownloads, wget_human_readable(quota_buf, sizeof(quota_buf), quota),
				wget_human_readable(speed_buf, sizeof(speed_buf), (quota*mod)/tdiff),
				rs_type, stats.nredirects, queue_size(), stats.nerrors
			);
	}
}

int main(int argc, const char **argv)
{
	int n, rc;
	char quota_buf[16];
	long long start_time = 0;

	_wget_init(); // initialize any resources belonging to this object file

	set_exit_status(WG_EXIT_STATUS_PARSE_INIT); // --version, --help etc might set the status to OK
	n = init(argc, argv);
	if (n < 0) {
		goto out;
	}
	set_exit_status(WG_EXIT_STATUS_NO_ERROR);

	for (; n < argc; n++) {
		add_url_to_queue(argv[n], config.base, config.local_encoding, 0);
	}

	if (config.input_file) {
		if (config.force_html) {
			// read URLs from HTML file
			html_parse_localfile(NULL, 0, config.input_file, config.input_encoding, config.base);
		}
		else if (config.force_css) {
			// read URLs from CSS file
			css_parse_localfile(NULL, config.input_file, config.input_encoding, config.base);
		}
		else if (config.force_sitemap) {
			// read URLs from Sitemap XML file (base is normally not needed, all URLs should be absolute)
			sitemap_parse_xml_localfile(NULL, config.input_file, "utf-8", config.base);
		}
		else if (config.force_atom) {
			// read URLs from Atom Feed XML file
			atom_parse_localfile(NULL, config.input_file, "utf-8", config.base);
		}
		else if (config.force_rss) {
			// read URLs from RSS Feed XML file
			rss_parse_localfile(NULL, config.input_file, "utf-8", config.base);
		}
		else if (config.force_metalink) {
			// read URLs from metalink XML file
			metalink_parse_localfile(config.input_file);
		}
//		else if (!wget_strcasecmp_ascii(config.input_file, "http://", 7)) {
//		}
		else if (!strcmp(config.input_file, "-")) {
			if (isatty(STDIN_FILENO)) {
				ssize_t len;
				size_t bufsize = 0;
				char *url, *buf = NULL;

				// read URLs from STDIN
				while ((len = wget_fdgetline(&buf, &bufsize, STDIN_FILENO)) >= 0) {
					for (url = buf; len && isspace(*url); url++, len--); // skip leading spaces
					if (*url == '#' || len <= 0) continue; // skip empty lines and comments
					for (;len && isspace(url[len - 1]); len--);  // skip trailing spaces
					// debug_printf("len=%zd url=%s\n", len, buf);

					url[len] = 0;
					add_url_to_queue(buf, config.base, config.input_encoding, 0);
				}
				xfree(buf);
			} else {
				// read URLs asynchronously and process each URL immediately when it arrives
				if ((rc = wget_thread_start(&input_tid, input_thread, NULL, 0)) != 0) {
					error_printf(_("Failed to start downloader, error %d\n"), rc);
				}
			}
		} else {
			int fd;
			ssize_t len;
			size_t bufsize = 0;
			char *url, *buf = 0;

			// read URLs from input file
			if ((fd = open(config.input_file, O_RDONLY|O_BINARY)) >= 0) {
				while ((len = wget_fdgetline(&buf, &bufsize, fd)) >= 0) {
					for (url = buf; len && isspace(*url); url++, len--); // skip leading spaces
					if (*url == '#' || len <= 0) continue; // skip empty lines and comments
					for (;len && isspace(url[len - 1]); len--);  // skip trailing spaces
					// debug_printf("len=%zd url=%s\n", len, buf);

					url[len] = 0;
					add_url_to_queue(url, config.base, config.input_encoding, 0);
				}
				xfree(buf);
				close(fd);
			} else
				error_printf(_("Failed to open input file %s\n"), config.input_file);
		}
	}

	if (queue_size() == 0 && !input_tid) {
		error_printf(_("Nothing to do - goodbye\n"));
		goto out;
	}

	// At this point, all values have been initialized and all URLs read.
	// Perform any sanity checking or extra initialization here.

	// Decide on the number of threads to spawn. In case we're reading
	// asynchronously from STDIN or are downloading recursively, we don't
	// know the queue_size at startup, and hence spawn config.max_threads
	// threads.
	if (!wget_thread_support()) {
		config.max_threads = 1;
		if (config.progress) {
			config.progress = 0;
			wget_info_printf(_("Wget2 built without thread support. Disabling progress report\n"));
		}
	}

	if (config.quiet) {
		if (!config.force_progress) {
			config.progress = 0;
		}
	}

	if (config.progress && !isatty(STDOUT_FILENO) && !config.force_progress) {
		config.progress = 0;
	}

	if (config.progress) {
		if (bar_init()) {
			wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), NULL);
			start_time = wget_get_timemillis();
		}
	}

	downloaders = wget_calloc(config.max_threads, sizeof(DOWNLOADER));

	wget_thread_mutex_lock(main_mutex);

	while (!terminate) {
		// queue_print();
		if (queue_empty() && !input_tid) {
			break;
		}

		for (;nthreads < config.max_threads && nthreads < queue_size(); nthreads++) {
			downloaders[nthreads].id = nthreads;

			// The actual number of nthreads is updated in the loop iteration
			// counter ater the iteration. So we add one already here to
			// account for it. The second extra slot is for the stats data that
			// is printed on the last line.
			if (config.progress)
				bar_update_slots(nthreads + 1 + 1);

			// start worker threads (I call them 'downloaders')
			if ((rc = wget_thread_start(&downloaders[nthreads].thread, downloader_thread, &downloaders[nthreads], 0)) != 0) {
				error_printf(_("Failed to start downloader, error %d\n"), rc);
			}
		}

		print_progress_report(start_time);

		if (config.quota && quota >= config.quota) {
			info_printf(_("Quota of %lld bytes reached - stopping.\n"), config.quota);
			break;
		}

		// here we sit and wait for an event from our worker threads
		wget_thread_cond_wait(main_cond, main_mutex, 0);
		debug_printf("%s: wake up\n", __func__);
	}
	debug_printf("%s: done\n", __func__);

	// stop downloaders
	terminate = 1;
	wget_thread_cond_signal(worker_cond);
	wget_thread_mutex_unlock(main_mutex);

	for (n = 0; n < nthreads; n++) {
		// if the thread is not detached, we have to call wget_thread_join()/wget_thread_timedjoin_np()
		// else we will have a huge memory leak
		//		if ((rc=wget_thread_timedjoin_np(downloader[n].tid, NULL, ms))!=0)
		if ((rc = wget_thread_join(&downloaders[n].thread)) != 0)
			error_printf(_("Failed to wait for downloader #%d (%d %d)\n"), n, rc, errno);
	}

	print_progress_report(start_time);
	if (!config.progress && (config.recursive || config.page_requisites || (config.input_file && quota != 0)) && quota) {
		info_printf(_("Downloaded: %d files, %s bytes, %d redirects, %d errors\n"),
			stats.ndownloads, wget_human_readable(quota_buf, sizeof(quota_buf), quota), stats.nredirects, stats.nerrors);
	}

	if (config.save_cookies)
		wget_cookie_db_save(config.cookie_db, config.save_cookies);

	if (config.hsts && config.hsts_file && hsts_changed)
		wget_hsts_db_save(config.hsts_db);

	if (config.hpkp && config.hpkp_file && hpkp_changed)
		wget_hpkp_db_save(config.hpkp_db);

	if (config.tls_resume && config.tls_session_file && wget_tls_session_db_changed(config.tls_session_db))
		wget_tls_session_db_save(config.tls_session_db, config.tls_session_file);

	if (config.ocsp && config.ocsp_file)
		wget_ocsp_db_save(config.ocsp_db);

	if (config.delete_after && config.output_document)
		unlink(config.output_document);

	if (config.debug)
		blacklist_print();

	if (config.convert_links && !config.delete_after) {
		_convert_links();
		wget_vector_free(&conversions);
	}

	stats_print();

 out:
	if (is_testing() || wget_match_tail(argv[0], "wget2_noinstall")) {
		// freeing to avoid disguising valgrind output
		blacklist_free();
		hosts_free();
		host_ips_free();
		xfree(downloaders);
		if (config.progress)
			bar_deinit();
		wget_vector_clear_nofree(parents);
		wget_vector_free(&parents);
		wget_hashmap_free(&known_urls);
		wget_stringmap_free(&etags);

		deinit();
		_wget_deinit(); // destroy any resources belonging to this object file
	}

	// Shutdown plugin system
	plugin_db_finalize(get_exit_status());

	return get_exit_status();
}

/*
 * This thread reads IRIs/URIs asynchronously from STDIN.
 *
 *  Wget2 starts working immediately after the first input since we have to be ready
 * for slow input (e.g. user typing or input from scripts with sleeps in between).
 *
 * We allow downloading of the same resource as often as a user likes to, so no
 * blacklisting is done in add_url_to_queue(). This makes it possible to use interactive
 * web services like a Tetris game by Igor Chubin:
 *
 * (b="http://te.ttr.is:8003"; echo $b; while read -sN1 a; do echo "$b/$a"; done) | wget2 --input-file=- -qO-
 *   h,j,k,l = left, down, turn, right; ctrl-c = stop
 */
void *input_thread(void *p G_GNUC_WGET_UNUSED)
{
	ssize_t len;
	size_t bufsize = 0;
	char *buf = NULL;

	while ((len = wget_fdgetline(&buf, &bufsize, STDIN_FILENO)) >= 0) {
		add_url_to_queue(buf, config.base, config.local_encoding, URL_FLG_NO_BLACKLISTING);

		if (nthreads < config.max_threads && nthreads < queue_size())
			// wake up main thread to recalculate # of workers
			wget_thread_cond_signal(main_cond);
		else
			// wake up all workers to check for
			wget_thread_cond_signal(worker_cond);
	}
	xfree(buf);

	// input closed, don't read from it any more
	debug_printf("input closed\n");

	// wake up main thread to take control (e.g. checking if we are done)
	wget_thread_cond_signal(main_cond);

	input_tid = 0;
	return NULL;
}

static int try_connection(DOWNLOADER *downloader, wget_iri_t *iri)
{
	wget_http_connection_t *conn;
	int rc;

	if (iri->scheme == WGET_IRI_SCHEME_HTTP) {
		bool match = 0;

		if (config.hsts && wget_hsts_host_match(config.hsts_db, iri->host, iri->port)) {
			match = 1;
		}
#ifdef WITH_LIBHSTS
		else if (config.hsts_preload && config.hsts_preload_data) {
			if (hsts_search(config.hsts_preload_data, iri->host, 0, NULL) == HSTS_SUCCESS) {
				match = 1;
			}
		}
#endif

		if (match) {
			info_printf(_("HSTS in effect for %s:%hu\n"), iri->host, iri->port);
			wget_iri_set_scheme(iri, WGET_IRI_SCHEME_HTTPS);
			host_add(iri);	// add new host to hosts
		}
	}

	if ((conn = downloader->conn)) {
		if (!wget_strcmp(wget_http_get_host(conn), iri->host) &&
			wget_http_get_scheme(conn) == iri->scheme &&
			wget_http_get_port(conn) == iri->port)
		{
			debug_printf("reuse connection %s\n", wget_http_get_host(conn));
			return WGET_E_SUCCESS;
		}

		debug_printf("close connection %s\n", wget_http_get_host(conn));
		wget_http_close(&downloader->conn);
	}

	if ((rc = wget_http_open(&downloader->conn, iri)) == WGET_E_SUCCESS) {
		debug_printf("established connection %s\n",
			wget_http_get_host(downloader->conn));
	} else {
		info_printf(_("Failed to connect: %s\n"), wget_strerror(rc));
	}

	return rc;
}

static int establish_connection(DOWNLOADER *downloader, wget_iri_t **iri)
{
	int rc = WGET_E_UNKNOWN;

	downloader->final_error = 0;

	if (downloader->job->part) {
		JOB *job = downloader->job;
		wget_metalink_t *metalink = job->metalink;
		PART *part = job->part;
		int mirror_count = wget_vector_size(metalink->mirrors);
		int mirror_index;

		if (mirror_count > 0)
			mirror_index = downloader->id % mirror_count;
		else {
			host_final_failure(downloader->job->host);
			set_exit_status(WG_EXIT_STATUS_NETWORK);
			return rc;
		}

		// we try every mirror max. 'config.tries' number of times
		for (int tries = 0; tries < config.tries && !part->done && !terminate; tries++) {
			wget_millisleep(tries * 1000 > config.waitretry ? config.waitretry : tries * 1000);

			if (terminate)
				break;

			for (int mirrors = 0; mirrors < wget_vector_size(metalink->mirrors) && !part->done; mirrors++) {
				wget_metalink_mirror_t *mirror = wget_vector_get(metalink->mirrors, mirror_index);

				mirror_index = (mirror_index + 1) % wget_vector_size(metalink->mirrors);

				if (mirror->iri->scheme == WGET_IRI_SCHEME_HTTP && config.https_enforce) {
					wget_iri_set_scheme(mirror->iri, WGET_IRI_SCHEME_HTTPS);
//					if (config.https_enforce == WGET_HTTPS_ENFORCE_SOFT)
//						http_fallback = 1;
				}

				rc = try_connection(downloader, mirror->iri);

				if (rc == WGET_E_SUCCESS) {

					// Add mirror URI to hosts
					host_add(mirror->iri);

					if (iri)
						*iri = mirror->iri;
					return rc;
				} else if (rc == WGET_E_TLS_DISABLED) {
					tries = config.tries;
					break;
				}
			}
		}
	} else {
		rc = try_connection(downloader, *iri);
	}

	if (rc == WGET_E_HANDSHAKE || rc == WGET_E_CERTIFICATE || rc == WGET_E_TLS_DISABLED) {
		// TLS  failure
		wget_http_close(&downloader->conn);
		if (!downloader->job->http_fallback) {
			host_final_failure(downloader->job->host);
			set_exit_status(WG_EXIT_STATUS_TLS);
		}
	} else if (rc == WGET_E_CONNECT) {
		/* failed to connect */
		wget_http_close(&downloader->conn);
		if (!config.retry_connrefused && !downloader->job->http_fallback) {
			host_final_failure(downloader->job->host);
			set_exit_status(WG_EXIT_STATUS_NETWORK);
		}
	}

	return rc;
}

static void add_statistics(wget_http_response_t *resp)
{
	// do some statistics
	JOB *job = resp->req->user_data;

	if (resp->code == 200) {
		if (job->part)
			_atomic_increment_int(&stats.nchunks);
		else
			_atomic_increment_int(&stats.ndownloads);
	} else if (resp->code == 301 || resp->code == 302  || resp->code == 303  || resp->code == 307  || resp->code == 308)
		_atomic_increment_int(&stats.nredirects);
	else if (resp->code == 304)
		_atomic_increment_int(&stats.nnotmodified);
	else
		_atomic_increment_int(&stats.nerrors);

	if (config.stats_site)
		stats_site_add(resp, NULL);
}

static int process_response_header(wget_http_response_t *resp)
{
	JOB *job = resp->req->user_data;
	DOWNLOADER *downloader = job->downloader;
	wget_iri_t *iri = job->iri;

	if (resp->code < 400 || resp->code > 599)
		print_status(downloader, "HTTP response %d %s [%s]\n", resp->code, resp->reason, iri->uri);
	else
		print_status(downloader, "HTTP ERROR response %d %s [%s]\n", resp->code, resp->reason, iri->uri);

	// Wget1.x compatibility
	if (resp->code/100 == 4 && resp->code != 416) {
		if (job->head_first)
			set_exit_status(WG_EXIT_STATUS_REMOTE);
		else if (resp->code == 404 && !job->robotstxt) {
#ifdef WITH_GPGME
			char *ext = wget_list_getfirst(job->remaining_sig_ext);
			if (!job->sig_req) {
				set_exit_status(WG_EXIT_STATUS_REMOTE);
			} else if (!ext) {
				if (config.verify_sig == WGET_GPG_VERIFY_SIG_FAIL)
					set_exit_status(WG_EXIT_STATUS_REMOTE);
			} else {
				char *next_check = wget_aprintf("%s.%s", job->sig_req, ext);
				wget_list_remove(&job->remaining_sig_ext, ext);
				add_url(job, "utf-8", next_check, URL_FLG_SIGNATURE_REQ);
				wget_xfree(next_check);
			}
#else
			set_exit_status(WG_EXIT_STATUS_REMOTE);
#endif
		}
	}

	// Server doesn't support keep-alive or want us to close the connection.
	// For HTTP2 connections this flag is always set.
	debug_printf("keep_alive=%d\n", resp->keep_alive);
	if (!resp->keep_alive)
		wget_http_close(&downloader->conn);

	// do some statistics
	add_statistics(resp);

	wget_cookie_normalize_cookies(job->iri, resp->cookies); // sanitize cookies
	wget_cookie_store_cookies(config.cookie_db, resp->cookies); // store cookies

	// care for HSTS feature
	if (config.hsts
		&& iri->scheme == WGET_IRI_SCHEME_HTTPS && !iri->is_ip_address
		&& resp->hsts)
	{
		wget_hsts_db_add(config.hsts_db, iri->host, iri->port, resp->hsts_maxage, resp->hsts_include_subdomains);
		hsts_changed = 1;
	}

	// HTTP Public-Key Pinning (RFC 7469)
	if (config.hpkp
		&& iri->scheme == WGET_IRI_SCHEME_HTTPS && !iri->is_ip_address
		&& resp->hpkp)
	{
		wget_hpkp_set_host(resp->hpkp, iri->host);
		wget_hpkp_db_add(config.hpkp_db, &resp->hpkp);
		hpkp_changed = 1;
	}

	if (resp->code == 302 && resp->links && resp->digests)
		return 0; // 302 with Metalink information

	if (resp->code == 401) { // Unauthorized
		job->auth_failure_count++;

		if (job->auth_failure_count > 1 || !resp->challenges) {
			// We already tried with credentials and they are wrong OR
			// The server sent no challenge. Don't try again.
			set_exit_status(WG_EXIT_STATUS_AUTH);
			return 1;
		}

		job->challenges = resp->challenges;
		job->challenges_alloc = true;
		resp->challenges = NULL;
		job->done = 0; // try again, but with challenge responses
		return 1; // stop further processing
	}

	if (resp->code == 407) { // Proxy Authentication Required
		if (job->proxy_challenges || !resp->challenges) {
			// We already tried with credentials and they are wrong OR
			// The proxy server sent no challenge. Don't try again.
			set_exit_status(WG_EXIT_STATUS_AUTH);
			return 1;
		}

		job->proxy_challenges = resp->challenges;
		resp->challenges = NULL;
		job->done = 0; // try again, but with challenge responses
		return 1; // stop further processing
	}

	if (resp->code == 416 && !resp->cur_downloaded) {
		info_printf(_("The file is already fully retrieved; nothing to do.\n"));
	}

	// 304 Not Modified
	if (resp->code / 100 == 2 || resp->code / 100 >= 4 || resp->code == 304)
		return 0; // final response

	if (resp->location) {
		wget_buffer_t uri_buf;
		char uri_sbuf[1024];

		wget_cookie_normalize_cookies(job->iri, resp->cookies);
		wget_cookie_store_cookies(config.cookie_db, resp->cookies);

		wget_buffer_init(&uri_buf, uri_sbuf, sizeof(uri_sbuf));

		wget_iri_relative_to_abs(iri, resp->location, strlen(resp->location), &uri_buf);

		if (uri_buf.length)
			add_url(job, "utf-8", uri_buf.data, URL_FLG_REDIRECTION);

		wget_buffer_deinit(&uri_buf);
	}

	return 0;
}

static bool check_status_code_list(wget_vector_t *list, uint16_t status);
static bool check_mime_list(wget_vector_t *list, const char *mime);

static void process_head_response(wget_http_response_t *resp)
{
	JOB *job = resp->req->user_data;

	job->head_first = 0;

	if (config.spider || !config.chunk_size) {
		if (resp->code != 200 || !resp->content_type)
			return;

		if (wget_strcasecmp_ascii(resp->content_type, "text/html")
			&& wget_strcasecmp_ascii(resp->content_type, "text/css")
			&& wget_strcasecmp_ascii(resp->content_type, "application/xhtml+xml")
			&& wget_strcasecmp_ascii(resp->content_type, "application/atom+xml")
			&& wget_strcasecmp_ascii(resp->content_type, "application/rss+xml")
			&& (!job->sitemap || !wget_strcasecmp_ascii(resp->content_type, "application/xml"))
			&& (!job->sitemap || !wget_strcasecmp_ascii(resp->content_type, "application/x-gzip"))
			&& (!job->sitemap || !wget_strcasecmp_ascii(resp->content_type, "text/plain"))
			&& (!config.mime_types || !check_mime_list(config.mime_types, resp->content_type)))
		{
			return;
		}

		if (resp->etag) {
			wget_thread_mutex_lock(etag_mutex);
			if (!etags)
				etags = wget_stringmap_create(128);
			int rc = wget_stringmap_put_noalloc(etags, resp->etag, NULL);
			resp->etag = NULL;
			wget_thread_mutex_unlock(etag_mutex);

			if (rc) {
				info_printf(_("Not scanning '%s' (known ETag)\n"), job->iri->uri);
				return;
			}
		}

		if (config.spider && !config.recursive)
			return; // if not -r then we are done

		job->done = 0; // do this job again with GET request
	} else if (config.chunk_size && resp->content_length > config.chunk_size) {
		// create metalink structure without hashing
		wget_metalink_piece_t piece = { .length = config.chunk_size };
		wget_metalink_mirror_t mirror = { .location = "-", .iri = job->iri };
		wget_metalink_t *metalink = wget_calloc(1, sizeof(wget_metalink_t));
		metalink->size = resp->content_length; // total file size
		metalink->name = wget_strdup(config.output_document ? config.output_document : job->local_filename);

		ssize_t npieces = (resp->content_length + config.chunk_size - 1) / config.chunk_size;
		metalink->pieces = wget_vector_create((int) npieces, NULL);
		for (int it = 0; it < npieces; it++) {
			piece.position = it * config.chunk_size;
			wget_vector_add(metalink->pieces, &piece, sizeof(wget_metalink_piece_t));
		}

		metalink->mirrors = wget_vector_create(1, NULL);

		wget_vector_add(metalink->mirrors, &mirror, sizeof(wget_metalink_mirror_t));

		job->metalink = metalink;

		// start or resume downloading
		if (!job_validate_file(job)) {
			// wake up sleeping workers
			wget_thread_cond_signal(worker_cond);
			job->done = 0; // do not remove this job from queue yet
		} // else file already downloaded and checksum ok
	} else if (config.chunk_size) {
		// server did not send Content-Length or chunk size <= Content-Length
		job->done = 0; // do not remove this job from queue yet
	}
}

// chunked or metalink partial download
static void process_response_part(wget_http_response_t *resp)
{
	JOB *job = resp->req->user_data;
	DOWNLOADER *downloader = job->downloader;
	PART *part = job->part;

	// just update number bytes read (body only) for display purposes
	if (resp->body)
		quota_modify_read(resp->cur_downloaded);

	if (resp->code != 200 && resp->code != 206) {
		print_status(downloader, "part %d download error %d\n", part->id, resp->code);
	} else if (!resp->body) {
		print_status(downloader, "part %d download error 'empty body'\n", part->id);
	} else if (resp->body->length != (size_t)part->length) {
		print_status(downloader, "part %d download error '%zu bytes of %lld expected'\n",
			part->id, resp->body->length, (long long)part->length);
	} else {
		print_status(downloader, "part %d downloaded\n", part->id);
		part->done = 1; // set this when downloaded ok
	}

	if (part->done) {
		// check if all parts are done (downloaded + hash-checked)
		int all_done = 1, it;

		wget_thread_mutex_lock(downloader_mutex);
		for (it = 0; it < wget_vector_size(job->parts); it++) {
			PART *partp = wget_vector_get(job->parts, it);
			if (!partp->done) {
				all_done = 0;
				break;
			}
		}
		wget_thread_mutex_unlock(downloader_mutex);

		if (all_done) {
			// check integrity of complete file
			if (config.progress)
				bar_print(downloader->id, "Checksumming...");
			else if (job->metalink)
				print_status(downloader, "%s checking...\n", job->metalink->name);
			else
				print_status(downloader, "%s checking...\n", job->local_filename);
			if (job_validate_file(job)) {
				if (config.progress)
					bar_print(downloader->id, "Checksum OK");
				else
					debug_printf("checksum ok\n");
				job->done = 1; // we are done with this job, main state machine will remove it
			} else {
				if (config.progress)
					bar_print(downloader->id, "Checksum FAILED");
				else
					debug_printf("checksum failed\n");
			}
		}
	} else {
		print_status(downloader, "part %d failed\n", part->id);
		part->inuse = 0; // something was wrong, reload again later
	}
}

static void process_response(wget_http_response_t *resp)
{
	JOB *job = resp->req->user_data;
	int process_decision = 0, recurse_decision = 0;

	// just update number bytes read (body only) for display purposes
	if (resp->body)
		quota_modify_read(resp->cur_downloaded);

	// check if we got a RFC 6249 Metalink response
	// HTTP/1.1 302 Found
	// Date: Fri, 20 Apr 2012 15:00:40 GMT
	// Server: Apache/2.2.22 (Linux/SUSE) mod_ssl/2.2.22 OpenSSL/1.0.0e DAV/2 SVN/1.7.4 mod_wsgi/3.3 Python/2.7.2 mod_asn/1.5 mod_mirrorbrain/2.17.0 mod_fastcgi/2.4.2
	// X-Prefix: 87.128.0.0/10
	// X-AS: 3320
	// X-MirrorBrain-Mirror: ftp.suse.com
	// X-MirrorBrain-Realm: country
	// Link: <http://go-oo.mirrorbrain.org/evolution/stable/Evolution-2.24.0.exe.meta4>; rel=describedby; type="application/metalink4+xml"
	// Link: <http://go-oo.mirrorbrain.org/evolution/stable/Evolution-2.24.0.exe.torrent>; rel=describedby; type="application/x-bittorrent"
	// Link: <http://ftp.suse.com/pub/projects/go-oo/evolution/stable/Evolution-2.24.0.exe>; rel=duplicate; pri=1; geo=de
	// Link: <http://ftp.hosteurope.de/mirror/ftp.suse.com/pub/projects/go-oo/evolution/stable/Evolution-2.24.0.exe>; rel=duplicate; pri=2; geo=de
	// Link: <http://ftp.isr.ist.utl.pt/pub/MIRRORS/ftp.suse.com/projects/go-oo/evolution/stable/Evolution-2.24.0.exe>; rel=duplicate; pri=3; geo=pt
	// Link: <http://suse.mirrors.tds.net/pub/projects/go-oo/evolution/stable/Evolution-2.24.0.exe>; rel=duplicate; pri=4; geo=us
	// Link: <http://ftp.kddilabs.jp/Linux/distributions/ftp.suse.com/projects/go-oo/evolution/stable/Evolution-2.24.0.exe>; rel=duplicate; pri=5; geo=jp
	// Digest: MD5=/sr/WFcZH1MKTyt3JHL2tA==
	// Digest: SHA=pvNwuuHWoXkNJMYSZQvr3xPzLZY=
	// Digest: SHA-256=5QgXpvMLXWCi1GpNZI9mtzdhFFdtz6tuNwCKIYbbZfU=
	// Location: http://ftp.suse.com/pub/projects/go-oo/evolution/stable/Evolution-2.24.0.exe
	// Content-Type: text/html; charset=iso-8859-1

	if (config.metalink && resp->links) {
		// Found a Metalink answer (RFC 6249 Metalink/HTTP: Mirrors and Hashes).
		// We try to find and download the .meta4 file (RFC 5854).
		// If we can't find the .meta4, download from the link with the highest priority.

		wget_http_link_t *top_link = NULL, *metalink = NULL;

		for (int it = 0; it < wget_vector_size(resp->links); it++) {
			wget_http_link_t *link = wget_vector_get(resp->links, it);
			if (link->rel == link_rel_describedby) {
				if (link->type && (!wget_strcasecmp_ascii(link->type, "application/metalink4+xml") ||
					 !wget_strcasecmp_ascii(link->type, "application/metalink+xml")))
				{
					// found a link to a metalink4 description
					metalink = link;
					break;
				}
			} else if (link->rel == link_rel_duplicate) {
				if (!top_link || top_link->pri > link->pri)
					// just save the top priority link
					top_link = link;
			}
		}

		if (metalink) {
			// found a link to a metalink3 or metalink4 description, create a new job
			add_url(job, "utf-8", metalink->uri, 0);
			return;
		} else if (top_link) {
			// no metalink4 description found, create a new job
			add_url(job, "utf-8", top_link->uri, 0);
			return;
		}
	}

	if (config.metalink && resp->content_type) {
		if (!wget_strcasecmp_ascii(resp->content_type, "application/metalink4+xml")
			|| !wget_strcasecmp_ascii(resp->content_type, "application/metalink+xml"))
		{
			// print_status(downloader, "get metalink info\n");
			// save_file(resp, job->local_filename, O_TRUNC);
			job->metalink = resp->body && resp->body->data ? wget_metalink_parse(resp->body->data) : NULL;
		}
		if (job->metalink) {
			if (job->metalink->size <= 0) {
				error_printf(_("File length %llu - remove job\n"), (unsigned long long)job->metalink->size);
			} else if (!job->metalink->mirrors) {
				error_printf(_("No download mirrors found - remove job\n"));
			} else {
				// just loaded a metalink description, create parts and sort mirrors

				// start or resume downloading
				if (!job_validate_file(job)) {
					// sort mirrors by priority to download from highest priority first
					wget_metalink_sort_mirrors(job->metalink);

					// wake up sleeping workers
					wget_thread_cond_signal(worker_cond);

					job->done = 0; // do not remove this job from queue yet
				} // else file already downloaded and checksum ok
			}
			return;
		}
	}

	// Forward response to plugins
	if (resp->code == 200 || resp->code == 206 || resp->code == 416 || (resp->code == 304 && config.timestamping)) {
		process_decision = job->local_filename || resp->body ? 1 : 0;
		recurse_decision = process_decision && config.recursive
			&& (!config.level || job->level < config.level + config.page_requisites) ? 1 : 0;
		if (process_decision) {
			wget_vector_t *recurse_iris = NULL;
			int n_recurse_iris = 0;
			const void *data = NULL;
			uint64_t size;
			const char *filename;

			if (config.spider || (config.recursive && config.output_document))
				filename = NULL;
			else
				filename = job->local_filename;

			if ((resp->code == 304 || resp->code == 416 || resp->code == 206) && filename)
				size = get_file_size(filename);
			else
				size = resp->content_length;

			if ((resp->code == 200 || resp->code == 206) && resp->body && resp->body->length == size)
				data = resp->body->data;

			if (recurse_decision)
				recurse_iris = wget_vector_create(16, NULL);

			process_decision = plugin_db_forward_downloaded_file(job->iri, size, filename, data, recurse_iris);

			if (recurse_decision) {
				n_recurse_iris = wget_vector_size(recurse_iris);
				for (int i = 0; i < n_recurse_iris; i++) {
					wget_iri_t *iri = (wget_iri_t *) wget_vector_get(recurse_iris, i);
					add_url(job, "utf-8", iri->uri, 0);
					wget_iri_free_content(iri);
				}
				wget_vector_free(&recurse_iris);
			}
		}
	}

	if (job->robotstxt &&
			// Only if a file was downloaded
			resp->body &&
			// Parse the robots file and only if it was successful
			(wget_robots_parse(&job->host->robots, resp->body->data, PACKAGE_NAME) == WGET_E_SUCCESS) &&
			// Sitemaps are not relevant as page requisites
			!config.page_requisites)
	{
		// add sitemaps to be downloaded (format https://www.sitemaps.org/protocol.html)
		for (int it = 0, n = wget_robots_get_sitemap_count(job->host->robots); it < n; it++) {
			const char *sitemap = wget_robots_get_sitemap(job->host->robots, it);
			debug_printf("adding sitemap '%s'\n", sitemap);
			add_url(job, "utf-8", sitemap, URL_FLG_SITEMAP); // see https://www.sitemaps.org/protocol.html#escaping
		}
	} else if (resp->code == 200 || resp->code == 206) {
		if (process_decision && recurse_decision) {
			if (resp->content_type && resp->body) {
				if (!wget_strcasecmp_ascii(resp->content_type, "text/html")) {
					html_parse(job, job->level, resp->body->data, resp->body->length, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
				} else if (!wget_strcasecmp_ascii(resp->content_type, "application/xhtml+xml")) {
					html_parse(job, job->level, resp->body->data, resp->body->length, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
					// xml_parse(sockfd, resp, job->iri);
				} else if (!wget_strcasecmp_ascii(resp->content_type, "text/css")) {
					css_parse(job, resp->body->data, resp->body->length, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
				} else if (!wget_strcasecmp_ascii(resp->content_type, "application/atom+xml")) { // see RFC4287, https://de.wikipedia.org/wiki/Atom_%28Format%29
					atom_parse(job, resp->body->data, "utf-8", job->iri);
				} else if (!wget_strcasecmp_ascii(resp->content_type, "application/rss+xml")) { // see https://cyber.harvard.edu/rss/rss.html
					rss_parse(job, resp->body->data, "utf-8", job->iri);
				} else if (job->sitemap) {
					if (!wget_strcasecmp_ascii(resp->content_type, "application/xml"))
						sitemap_parse_xml(job, resp->body->data, "utf-8", job->iri);
					else if (!wget_strcasecmp_ascii(resp->content_type, "application/x-gzip"))
						sitemap_parse_xml_gz(job, resp->body, "utf-8", job->iri);
					else if (!wget_strcasecmp_ascii(resp->content_type, "text/plain"))
						sitemap_parse_text(job, resp->body->data, "utf-8", job->iri);
				}
			}
		}
		else if (config.verify_sig != WGET_GPG_VERIFY_DISABLED
			 && resp->content_type) {
#ifdef WITH_GPGME
			if (wget_strcasecmp_ascii(resp->content_type, "application/pgp-signature") == 0) {

				wget_gpg_info_t info;

				if (wget_verify_job(job, resp, &info) != WGET_E_SUCCESS) {
					set_exit_status(WG_EXIT_STATUS_GPG_ERROR);
					if (!config.verify_save_failed) {
						char *base_path = wget_verify_get_base_file(job);
						if (base_path) {
							unlink(base_path);
							wget_free(base_path);
						} else {
							error_printf(_("Couldn't determine base file to delete for failed verification\n"));
						}
					}
				} else {
					wget_info_printf(_("Signature for file %s successfully verified\n"), job->local_filename);
				}

				// Remove the signature file.
				unlink(job->local_filename);

				if (config.stats_site)
					stats_site_add(resp, &info);

			} else if (wget_strncasecmp_ascii(resp->content_type, "application/", 12) == 0) {

				if (config.sig_ext) {
					int ext_count = wget_vector_size(config.sig_ext);
					if (ext_count > 0) {

						if (job->remaining_sig_ext) {
							error_printf(_("Should not have remaining extensions!\n"));
							wget_list_free(&job->remaining_sig_ext);
						}

						// Note: starting at 1 (not 0), first URL is the ext at idx 0
						for (int ext_idx = 1; ext_idx < ext_count; ext_idx++) {
							const char *e = (const char *) wget_vector_get(config.sig_ext, ext_idx);
							wget_list_append(&job->remaining_sig_ext, e, strlen(e) + 1);
						}

						char *first_check = wget_aprintf(
							"%s.%s", job->original_url->uri, (const char *) wget_vector_get(config.sig_ext, 0));

						if (!job->sig_filename)
							error_printf(_("File name for signature checking not assigned to job!\n"));
						else if (job->sig_req)
							error_printf(_("Cannot check the signature on a signature!\n"));
						else
							add_url(job, "utf-8", first_check, URL_FLG_SIGNATURE_REQ);

						wget_free(first_check);

					}
				}
			}
#endif
		}
	}
	else if ((resp->code == 304 && config.timestamping) || resp->code == 416) { // local document is up-to-date
		if (process_decision && recurse_decision) {
			const char *local_filename;

			if (config.content_disposition && resp->content_filename)
				local_filename = resp->content_filename;
			else
				local_filename = job->local_filename;

			parse_localfile(job, local_filename, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, resp->content_type, job->iri);
		}
	}
}

static void _fallback_to_http(JOB *job)
{
	if (!job->robotstxt) {
		char *http_url = wget_aprintf("http://%s", job->iri->uri + 8);
		add_url(NULL, "utf-8", http_url, URL_FLG_SKIPFALLBACK);
		host_remove_job(job->host, job);
		xfree(http_url);
	} else {
		host_remove_job(job->host, job);
	}
}

enum actions {
	ACTION_GET_JOB = 1,
	ACTION_GET_RESPONSE = 2,
	ACTION_ERROR = 3
};

void *downloader_thread(void *p)
{
	DOWNLOADER *downloader = p;
	wget_http_response_t *resp = NULL;
	JOB *job;
	HOST *host = NULL;
	int pending = 0, max_pending = 1, locked;
	long long pause = 0;
	enum actions action = ACTION_GET_JOB;
	char http_code[7];

	// downloader->thread = wget_thread_self(); // to avoid race condition

	wget_thread_mutex_lock(main_mutex); locked = 1;

	while (!terminate) {
		debug_printf("[%d] action=%d pending=%d host=%p\n", downloader->id, (int) action, pending, (void *) host);

		switch (action) {
		case ACTION_GET_JOB: // Get a job, connect, send request
			if (!(job = host_get_job(host, &pause))) {
				if (pending) {
					wget_thread_mutex_unlock(main_mutex); locked = 0;
					action = ACTION_GET_RESPONSE;
				} else if (host) {
					wget_http_close(&downloader->conn);
					host = NULL;
				} else {
					if (!wget_thread_support()) {
						if (!pause)
							goto out;

						wget_millisleep(pause);
						continue;
					}
					wget_thread_cond_wait(worker_cond, main_mutex, pause); locked = 1;
				}
				break;
			}

			wget_thread_mutex_unlock(main_mutex); locked = 0;

			{
				wget_iri_t *iri = job->iri;
				downloader->job = job;
				job->downloader = downloader;

				if (++pending == 1) {
					host = job->host;

					if (establish_connection(downloader, &iri) != WGET_E_SUCCESS) {
						if (job->http_fallback)
							_fallback_to_http(job);
						else
							host_increase_failure(host);
						action = ACTION_ERROR;
						break;
					}

					job->iri = iri;
					if (config.wait || job->metalink || !downloader->conn || wget_http_get_protocol(downloader->conn) != WGET_PROTOCOL_HTTP_2_0)
						max_pending = 1;
					else
						max_pending = config.http2_request_window;
				}

				// wait between sending requests
				if (config.wait) {
					if (config.random_wait)
						wget_millisleep(rand() % config.wait + config.wait / 2); // (0.5 - 1.5) * config.wait
					else
						wget_millisleep(config.wait);

					if (terminate)
						break;
				}

				if (!job->original_url)
					job->original_url = iri;

				if (http_send_request(job->iri, job->original_url, downloader) != WGET_E_SUCCESS) {
					if (job->http_fallback)
						_fallback_to_http(job);
					else
						host_increase_failure(host);
					action = ACTION_ERROR;
					break;
				}

				if (pending >= max_pending) {
					action = ACTION_GET_RESPONSE;
				} else {
					wget_thread_mutex_lock(main_mutex); locked = 1;
				}
			}
			break;

		case ACTION_GET_RESPONSE:
			resp = http_receive_response(downloader->conn);

			if (config.http_retry_on_status && resp && resp->code != 200) {
				wget_snprintf(http_code, sizeof(http_code), "%d", resp->code);
				if (check_mime_list(config.http_retry_on_status, http_code)) {
					print_status(downloader, "Got a HTTP Code %d. Retrying...", resp->code);
					wget_http_free_request(&resp->req);
					wget_http_free_response(&resp);
				}
			}

			if (!resp) {
				// likely that the other side closed the connection, try again
				host_increase_failure(host);
				action = ACTION_ERROR;
				break;
			}

			host_reset_failure(host);

			job = resp->req->user_data;

			// general response check to see if we need further processing
			if (process_response_header(resp) == 0) {
				if (job->head_first)
					process_head_response(resp); // HEAD request/response
				else if (job->part)
					process_response_part(resp); // chunked/metalink GET download
				else
					process_response(resp); // GET + POST request/response
			}

			wget_http_free_request(&resp->req);
			wget_http_free_response(&resp);

			wget_thread_mutex_lock(main_mutex); locked = 1;

			// download of single-part file complete, remove from job queue
			if (job->done) {
				host_remove_job(host, job);
			} else {
				job->inuse = 0;
			}

			wget_thread_cond_signal(main_cond);

			pending--;
			action = ACTION_GET_JOB;

			break;

		case ACTION_ERROR:
			wget_http_close(&downloader->conn);

			wget_thread_mutex_lock(main_mutex); locked = 1;
			host_release_jobs(host);
			wget_thread_cond_signal(main_cond);

			host = NULL;
			pending = 0;

			action = ACTION_GET_JOB;
			break;

		default:
			error_printf_exit(_("Unhandled action %d\n"), (int) action);
		}
	}

out:
	if (locked)
		wget_thread_mutex_unlock(main_mutex);
	wget_http_close(&downloader->conn);

	// if we terminate, tell the other downloaders
	wget_thread_cond_signal(worker_cond);

	return NULL;
}

static void _free_conversion_entry(_conversion_t *conversion)
{
	xfree(conversion->filename);
	xfree(conversion->encoding);
	wget_iri_free(&conversion->base_url);
	wget_html_free_urls_inline(&conversion->parsed);
}

static void _remember_for_conversion(const char *filename, wget_iri_t *base_url, int content_type, const char *encoding, wget_html_parsed_result_t *parsed)
{
	_conversion_t conversion;

	conversion.filename = wget_strdup(filename);
	conversion.encoding = wget_strdup(encoding);
	conversion.base_url = wget_iri_clone(base_url);
	conversion.content_type = content_type;
	conversion.parsed = parsed;

	wget_thread_mutex_lock(conversion_mutex);

	if (!conversions) {
		conversions = wget_vector_create(128, NULL);
		wget_vector_set_destructor(conversions, (wget_vector_destructor_t)_free_conversion_entry);
	}

	wget_vector_add(conversions, &conversion, sizeof(conversion));

	wget_thread_mutex_unlock(conversion_mutex);
}

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned int G_GNUC_WGET_PURE hash_url(const char *url)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter

	while (*url)
		hash = hash * 101 + (unsigned char)*url++;

	return hash;
}

/*
 * helper function: percent-unescape, convert to utf-8, create URL string using base
 */
static int _normalize_uri(wget_iri_t *base, wget_string_t *url, const char *encoding, wget_buffer_t *buf)
{
	char *urlpart = wget_strmemdup(url->p, url->len);
	char *urlpart_encoded;
	size_t urlpart_encoded_length;
	int rc;

	// ignore e.g. href='#'
	if (url->len == 0 || (url->len >= 1 && *url->p == '#')) {
		xfree(urlpart);
		return -1;
	}

	wget_iri_unescape_url_inline(urlpart);
	rc = wget_memiconv(encoding, urlpart, strlen(urlpart), "utf-8", &urlpart_encoded, &urlpart_encoded_length);
	xfree(urlpart);

	if (rc) {
		info_printf(_("URL '%.*s' not followed (conversion failed)\n"), (int)url->len, url->p);
		return -2;
	}

	rc = !wget_iri_relative_to_abs(base, urlpart_encoded, urlpart_encoded_length, buf);
	xfree(urlpart_encoded);

	if (rc) {
		error_printf(_("Cannot resolve relative URI %.*s\n"), (int)url->len, url->p);
		return -3;
	}

	return 0;
}

void html_parse(JOB *job, int level, const char *html, size_t html_len, const char *encoding, wget_iri_t *base)
{
	wget_iri_t *allocated_base = NULL;
	const char *reason;
	char *utf8 = NULL;
	wget_buffer_t buf;
	char sbuf[1024];
	int convert_links = config.convert_links && !config.delete_after;
	bool page_requisites = config.recursive && config.page_requisites && config.level && level < config.level;

	//	info_printf(_("page_req %d: %d %d %d %d\n"), page_requisites, config.recursive, config.page_requisites, config.level, level);

	// https://html.spec.whatwg.org/#determining-the-character-encoding
	if (encoding && encoding == config.remote_encoding) {
		reason = _("set by user");
	} else {
		if ((unsigned char)html[0] == 0xFE && (unsigned char)html[1] == 0xFF) {
			// Big-endian UTF-16
			encoding = "UTF-16BE";
			reason = _("set by BOM");

			// adjust behind BOM, ignore trailing single byte
			html += 2;
			html_len -= 2;
		} else if ((unsigned char)html[0] == 0xFF && (unsigned char)html[1] == 0xFE) {
			// Little-endian UTF-16
			encoding = "UTF-16LE";
			reason = _("set by BOM");

			// adjust behind BOM
			html += 2;
			html_len -= 2;
		} else if ((unsigned char)html[0] == 0xEF && (unsigned char)html[1] == 0xBB && (unsigned char)html[2] == 0xBF) {
			// UTF-8
			encoding = "UTF-8";
			reason = _("set by BOM");

			// adjust behind BOM
			html += 3;
			html_len -= 3;
		} else
			reason = _("set by server response");
	}

	if (!wget_strncasecmp_ascii(encoding, "UTF-16", 6)) {
		size_t n;

		html_len -= html_len & 1; // ignore single trailing byte, else charset conversion fails

		if (wget_memiconv(encoding, html, html_len, "UTF-8", &utf8, &n) == 0) {
			info_printf(_("Convert non-ASCII encoding '%s' (%s) to UTF-8\n"), encoding, reason);
			html = utf8;
			if (convert_links) {
				convert_links = 0; // prevent link conversion
				info_printf(_("Link conversion disabled for '%s'\n"), job->local_filename);
			}

		} else {
			info_printf(_("Failed to convert non-ASCII encoding '%s' (%s) to UTF-8, skip parsing\n"), encoding, reason);
			return;
		}
	}

	wget_html_parsed_result_t *parsed  = wget_html_get_urls_inline(html, config.follow_tags, config.ignore_tags);

	if (config.robots && !parsed->follow)
		goto cleanup;

	if (!encoding) {
		if (parsed->encoding) {
			encoding = parsed->encoding;
			reason = _("set by document");
		} else {
			encoding = "CP1252"; // default encoding for HTML5 (pre-HTML5 is iso-8859-1)
			reason = _("default, encoding not specified");
		}
	}

	info_printf(_("URI content encoding = '%s' (%s)\n"), encoding, reason);

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	if (parsed->base.p) {
		if (_normalize_uri(base, &parsed->base, encoding, &buf) == 0) {
			// info_printf("%.*s -> %s\n", (int)parsed->base.len, parsed->base.p, buf.data);
			if (!base && !buf.length)
				info_printf(_("BASE '%.*s' not usable (missing absolute base URI)\n"), (int)parsed->base.len, parsed->base.p);
			else {
				wget_iri_t *newbase = wget_iri_parse(buf.data, "utf-8");
				if (newbase)
					base = allocated_base = newbase;
			}
		} else {
			error_printf(_("Cannot resolve BASE URI %.*s\n"), (int)parsed->base.len, parsed->base.p);
		}
	}

	wget_thread_mutex_lock(known_urls_mutex);

	for (int it = 0; it < wget_vector_size(parsed->uris); it++) {
		wget_html_parsed_url_t *html_url = wget_vector_get(parsed->uris, it);
		wget_string_t *url = &html_url->url;

		/* do not follow action and formation at all */
		if (!wget_strcasecmp_ascii(html_url->attr, "action") || !wget_strcasecmp_ascii(html_url->attr, "formaction")) {
			info_printf(_("URL '%.*s' not followed (action/formaction attribute)\n"), (int)url->len, url->p);
			continue;
		}

		// with --page-requisites: just load inline URLs from the deepest level documents
		if (page_requisites && !wget_strcasecmp_ascii(html_url->attr, "href")) {
			// don't load from dir 'A', 'AREA' and 'EMBED'
			// only load from dir 'LINK' when rel was 'icon shortcut' or 'stylesheet'
			if ((c_tolower(*html_url->dir) == 'a'
				&& (html_url->dir[1] == 0 || !wget_strcasecmp_ascii(html_url->dir,"area")))
				|| !html_url->link_inline
				|| !wget_strcasecmp_ascii(html_url->dir,"embed")) {
				info_printf(_("URL '%.*s' not followed (page requisites + level)\n"), (int)url->len, url->p);
				continue;
			}
		}

		if (_normalize_uri(base, url, encoding, &buf))
			continue;

		// info_printf("%.*s -> %s\n", (int)url->len, url->p, buf.data);
		if (!base && !buf.length)
			info_printf(_("URL '%.*s' not followed (missing base URI)\n"), (int)url->len, url->p);
		else {
			// Blacklist for URLs before they are processed
			if (wget_hashmap_put_noalloc(known_urls, wget_strmemdup(buf.data, buf.length), NULL) == 0)
				add_url(job, "utf-8", buf.data, page_requisites ? URL_FLG_REQUISITE : 0);
		}
	}
	wget_thread_mutex_unlock(known_urls_mutex);

	wget_buffer_deinit(&buf);

	if (convert_links && !config.delete_after) {
		for (int it = 0; it < wget_vector_size(parsed->uris); it++) {
			wget_html_parsed_url_t *html_url = wget_vector_get(parsed->uris, it);
			html_url->url.p = (const char *) (html_url->url.p - html); // convert pointer to offset
		}
		_remember_for_conversion(job->local_filename, base, _CONTENT_TYPE_HTML, encoding, parsed);
		parsed = NULL; // 'parsed' has been consumed
	}

	wget_iri_free(&allocated_base);

cleanup:
	wget_html_free_urls_inline(&parsed);
	xfree(utf8);
}

void html_parse_localfile(JOB *job, int level, const char *fname, const char *encoding, wget_iri_t *base)
{
	char *data;
	size_t n;

	if ((data = wget_read_file(fname, &n))) {
		html_parse(job, level, data, n, encoding, base);
	}

	xfree(data);
}

void sitemap_parse_xml(JOB *job, const char *data, const char *encoding, wget_iri_t *base)
{
	wget_vector_t *urls, *sitemap_urls;
	const char *p;
	size_t baselen = 0;

	wget_sitemap_get_urls_inline(data, &urls, &sitemap_urls);

	if (base) {
		if ((p = strrchr(base->uri, '/')))
			baselen = p - base->uri + 1; // + 1 to include /
		else
			baselen = strlen(base->uri);
	}

	// process the sitemap urls here
	info_printf(_("found %d url(s) (base=%s)\n"), wget_vector_size(urls), base ? base->uri : NULL);
	wget_thread_mutex_lock(known_urls_mutex);
	for (int it = 0; it < wget_vector_size(urls); it++) {
		wget_string_t *url = wget_vector_get(urls, it);

		// A Sitemap file located at https://example.com/catalog/sitemap.xml can include any URLs starting with https://example.com/catalog/
		// but not any other.
		if (baselen && (url->len <= baselen || wget_strncasecmp(url->p, base->uri, baselen))) {
			info_printf(_("URL '%.*s' not followed (not matching sitemap location)\n"), (int)url->len, url->p);
			continue;
		}

		// Blacklist for URLs before they are processed
		if (wget_hashmap_put_noalloc(known_urls, (p = wget_strmemdup(url->p, url->len)), NULL)) {
			// the dup'ed url has already been freed when we come here
			info_printf(_("URL '%.*s' not followed (already known)\n"), (int)url->len, url->p);
			continue;
		}

		add_url(job, encoding, p, 0);
	}

	// process the sitemap index urls here
	info_printf(_("found %d sitemap url(s) (base=%s)\n"), wget_vector_size(sitemap_urls), base ? base->uri : NULL);
	for (int it = 0; it < wget_vector_size(sitemap_urls); it++) {
		wget_string_t *url = wget_vector_get(sitemap_urls, it);

		// TODO: url must have same scheme, port and host as base

		// Blacklist for URLs before they are processed
		if (wget_hashmap_put_noalloc(known_urls, (p = wget_strmemdup(url->p, url->len)), NULL)) {
			// the dup'ed url has already been freed when we come here
			info_printf(_("URL '%.*s' not followed (already known)\n"), (int)url->len, url->p);
			continue;
		}

		add_url(job, encoding, p, URL_FLG_SITEMAP);
	}
	wget_thread_mutex_unlock(known_urls_mutex);

	wget_vector_free(&urls);
	wget_vector_free(&sitemap_urls);
	// wget_sitemap_free_urls_inline(&res);
}

static int _get_unzipped(void *userdata, const char *data, size_t length)
{
	wget_buffer_memcat((wget_buffer_t *)userdata, data, length);

	return 0;
}

void sitemap_parse_xml_gz(JOB *job, wget_buffer_t *gzipped_data, const char *encoding, wget_iri_t *base)
{
	wget_buffer_t *plain = wget_buffer_alloc(gzipped_data->length * 10);
	wget_decompressor_t *dc = NULL;

	if ((dc = wget_decompress_open(wget_content_encoding_gzip, _get_unzipped, plain))) {
		wget_decompress(dc, gzipped_data->data, gzipped_data->length);
		wget_decompress_close(dc);

		sitemap_parse_xml(job, plain->data, encoding, base);
	} else
		error_printf(_("Can't scan '%s' because no libz support enabled at compile time\n"), job->iri->uri);

	wget_buffer_free(&plain);
}

void sitemap_parse_xml_localfile(JOB *job, const char *fname, const char *encoding, wget_iri_t *base)
{
	char *data;

	if ((data = wget_read_file(fname, NULL)))
		sitemap_parse_xml(job, data, encoding, base);

	xfree(data);
}

void sitemap_parse_text(JOB *job, const char *data, const char *encoding, wget_iri_t *base)
{
	size_t baselen = 0;
	const char *end, *line, *p;
	size_t len;

	if (base) {
		if ((p = strrchr(base->uri, '/')))
			baselen = p - base->uri + 1; // + 1 to include /
		else
			baselen = strlen(base->uri);
	}

	// also catch the case where the last line isn't terminated by '\n'
	for (line = end = data; *end && (end = (p = strchr(line, '\n')) ? p : line + strlen(line)); line = end + 1) {
		// trim
		len = end - line;
		for (;len && isspace(*line); line++, len--); // skip leading spaces
		for (;len && isspace(line[len - 1]); len--);  // skip trailing spaces

		if (len) {
			// A Sitemap file located at https://example.com/catalog/sitemap.txt can include any URLs starting with https://example.com/catalog/
			// but not any other.
			if (baselen && (len <= baselen || wget_strncasecmp(line, base->uri, baselen))) {
				info_printf(_("URL '%.*s' not followed (not matching sitemap location)\n"), (int)len, line);
			} else if (len < 1024) {
				char url[len + 1];

				memcpy(url, line, len);
				url[len] = 0;

				add_url(job, encoding, url, 0);
			} else {
				char *url = wget_strmemdup(line, len);
				add_url(job, encoding, url, 0);
				xfree(url);
			}
		}
	}
}

static void _add_urls(JOB *job, wget_vector_t *urls, const char *encoding, wget_iri_t *base)
{
	const char *p;
	size_t baselen = 0;

	if (base) {
		if ((p = strrchr(base->uri, '/')))
			baselen = p - base->uri + 1; // + 1 to include /
		else
			baselen = strlen(base->uri);
	}

	info_printf(_("found %d url(s) (base=%s)\n"), wget_vector_size(urls), base ? base->uri : NULL);

	wget_thread_mutex_lock(known_urls_mutex);
	for (int it = 0; it < wget_vector_size(urls); it++) {
		wget_string_t *url = wget_vector_get(urls, it);

		if (baselen && (url->len <= baselen || wget_strncasecmp(url->p, base->uri, baselen))) {
			info_printf(_("URL '%.*s' not followed (not matching sitemap location)\n"), (int)url->len, url->p);
			continue;
		}

		// Blacklist for URLs before they are processed
		if (wget_hashmap_put_noalloc(known_urls, (p = wget_strmemdup(url->p, url->len)), NULL)) {
			// the dup'ed url has already been freed when we come here
			info_printf(_("URL '%.*s' not followed (already known)\n"), (int)url->len, url->p);
			continue;
		}

		add_url(job, encoding, p, 0);
	}
	wget_thread_mutex_unlock(known_urls_mutex);
}

void atom_parse(JOB *job, const char *data, const char *encoding, wget_iri_t *base)
{
	wget_vector_t *urls;

	wget_atom_get_urls_inline(data, &urls);
	_add_urls(job, urls, encoding, base);
	wget_vector_free(&urls);
	// wget_atom_free_urls_inline(&res);
}

void atom_parse_localfile(JOB *job, const char *fname, const char *encoding, wget_iri_t *base)
{
	char *data;

	if ((data = wget_read_file(fname, NULL)))
		atom_parse(job, data, encoding, base);

	xfree(data);
}

void rss_parse(JOB *job, const char *data, const char *encoding, wget_iri_t *base)
{
	wget_vector_t *urls;

	wget_rss_get_urls_inline(data, &urls);
	_add_urls(job, urls, encoding, base);
	wget_vector_free(&urls);
	// wget_rss_free_urls_inline(&res);
}

void rss_parse_localfile(JOB *job, const char *fname, const char *encoding, wget_iri_t *base)
{
	char *data;

	if ((data = wget_read_file(fname, NULL)))
		rss_parse(job, data, encoding, base);

	xfree(data);
}

void metalink_parse_localfile(const char *fname)
{
	char *data;

	if ((data = wget_read_file(fname, NULL))) {
		wget_metalink_t *metalink = wget_metalink_parse(data);

		if (metalink->size <= 0) {
			error_printf(_("Invalid file length %llu\n"), (unsigned long long)metalink->size);
			wget_metalink_free(&metalink);
		} else if (!metalink->mirrors) {
			error_printf(_("No download mirrors found\n"));
			wget_metalink_free(&metalink);
		} else {
			// create parts and sort mirrors
			JOB job = { .metalink = metalink };

			// start or resume downloading
			if (!job_validate_file(&job)) {
				// sort mirrors by priority to download from highest priority first
				wget_metalink_sort_mirrors(metalink);

				// we have to attach the job to a host - take the first mirror for this purpose
				wget_metalink_mirror_t *mirror = wget_vector_get(metalink->mirrors, 0);

				HOST *host;
				if (!(host = host_add(mirror->iri)))
					host = host_get(mirror->iri);

				host_add_job(host, &job);
			} else { // file already downloaded and checksum ok
				wget_metalink_free(&metalink);
			}
		}

		xfree(data);
	}
}

struct css_context {
	JOB
		*job;
	wget_iri_t
		*base;
	const char
		*encoding;
	wget_buffer_t
		uri_buf;
	char
		encoding_allocated;
};

static void _css_parse_encoding(void *context, const char *encoding, size_t len)
{
	struct css_context *ctx = context;

	// take only the first @charset rule
	if (!ctx->encoding_allocated && wget_strncasecmp_ascii(ctx->encoding, encoding, len)) {
		ctx->encoding = wget_strmemdup(encoding, len);
		ctx->encoding_allocated = 1;
		info_printf(_("URI content encoding = '%s'\n"), ctx->encoding);
	}
}

static void _css_parse_uri(void *context, const char *url, size_t len, size_t pos G_GNUC_WGET_UNUSED)
{
	struct css_context *ctx = context;
	wget_string_t u = { url, len };

	if (_normalize_uri(ctx->base, &u, ctx->encoding, &ctx->uri_buf))
		return;

	// we assume every URL() in a CSS file being a page requisite, URL_FLG_REQUISITE skips --no-parent
	if (!ctx->base && !ctx->uri_buf.length)
		info_printf(_("URL '%.*s' not followed (missing base URI)\n"), (int)len, url);
	else
		add_url(ctx->job, ctx->encoding, ctx->uri_buf.data, URL_FLG_REQUISITE);
}

void css_parse(JOB *job, const char *data, size_t len, const char *encoding, wget_iri_t *base)
{
	// create scheme://authority that will be prepended to relative paths
	struct css_context context = { .base = base, .job = job, .encoding = encoding };
	char sbuf[1024];

	wget_buffer_init(&context.uri_buf, sbuf, sizeof(sbuf));

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	wget_css_parse_buffer(data, len, _css_parse_uri, _css_parse_encoding, &context);

	if (context.encoding_allocated)
		xfree(context.encoding);

	wget_buffer_deinit(&context.uri_buf);
}

void css_parse_localfile(JOB *job, const char *fname, const char *encoding, wget_iri_t *base)
{
	// create scheme://authority that will be prepended to relative paths
	struct css_context context = { .base = base, .job = job, .encoding = encoding };
	char sbuf[1024];

	wget_buffer_init(&context.uri_buf, sbuf, sizeof(sbuf));

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	wget_css_parse_file(fname, _css_parse_uri, _css_parse_encoding, &context);

	if (context.encoding_allocated)
		xfree(context.encoding);

	wget_buffer_deinit(&context.uri_buf);
}

static long long G_GNUC_WGET_NONNULL_ALL get_file_size(const char *fname)
{
	struct stat st;

	if (stat(fname, &st)==0) {
		return st.st_size;
	}

	return 0;
}

static time_t G_GNUC_WGET_NONNULL_ALL get_file_mtime(const char *fname)
{
	struct stat st;

	if (stat(fname, &st)==0) {
		return st.st_mtime;
	}

	return 0;
}

static void set_file_mtime(int fd, time_t modified)
{
	struct timespec timespecs[2]; // [0]=last access  [1]=last modified

	gettime(&timespecs[0]);

	timespecs[1].tv_sec = modified;
	timespecs[1].tv_nsec = 0;

	if (futimens(fd, timespecs) == -1)
		error_printf (_("Failed to set file date: %s\n"), strerror (errno));
}

// On windows, open() and fopen() return EACCES instead of EISDIR.
static int _wa_open(const char *fname, int flags, mode_t mode) {
	int fd = open(fname, flags, mode);
#ifdef _WIN32
	if (fd < 0 && errno == EACCES) {
		DWORD attrs = GetFileAttributes(fname);
		if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
			errno = EISDIR;
	}
#endif
	return fd;
}

// Opens files uniquely
static int _open_unique(const char *fname, int flags, mode_t mode, int multiple, char *unique, size_t unique_len)
{
	int fd;

	if (unique_len && unique[0])
		return _wa_open(unique, flags, mode);

	fd = _wa_open(fname, flags, mode);
	if (fd >= 0)
		return fd;

	if (config.keep_extension) {
		const char *ext = strrchr(fname, '.');

		if (!ext)
			ext = fname + strlen(fname);

		for (int i = 1; i < 99999 && fd < 0 && ((multiple && errno == EEXIST) || errno == EISDIR); i++) {
			if (wget_snprintf(unique, unique_len, "%.*s_%d%s", (int) (ext - fname), fname, i, ext) >= unique_len)
				return -1;
			fd = _wa_open(unique, flags, mode);
		}
	} else {
		for (int i = 1; i < 99999 && fd < 0 && ((multiple && errno == EEXIST) || errno == EISDIR); i++) {
			if (wget_snprintf(unique, unique_len, "%s.%d", fname, i) >= unique_len)
				return -1;
			fd = _wa_open(unique, flags, mode);
		}
	}

	return fd;
}

// return 0 if mime won't be downloaded and 1 if it will
static bool check_mime_list(wget_vector_t *list, const char *mime)
{
	char result = 0;

	for (int i = 0; i < wget_vector_size(list); i++) {
		char *entry = wget_vector_get(list, i);
		bool exclude = (*entry == '!');

		debug_printf("mime check %s - %s", entry, mime);

		entry += exclude;

		if (strpbrk(entry, "*?[]") && !fnmatch(entry, mime, FNM_CASEFOLD))
			result = !exclude;
		else if (!wget_strcasecmp(entry, mime))
			result = !exclude;
	}

	debug_printf("mime check %d", result);
	return result;
}

static int G_GNUC_WGET_NONNULL((1)) _prepare_file(wget_http_response_t *resp, const char *fname, int flag,
		wget_iri_t *uri, wget_iri_t *original_url, int ignore_patterns, wget_buffer_t *partial_content,
		size_t max_partial_content, char **actual_file_name, const char *path)
{
	JOB *job = resp->req->user_data;
	char *alloced_fname = NULL;
	int fd, multiple = 0, oflag = flag;
	size_t fname_length;
	long long old_quota;

	if (!fname)
		return -1;

	if (config.spider) {
		debug_printf("not saved '%s' (spider mode enabled)\n", fname);
		return -1;
	}

	if (config.mime_types && !check_mime_list(config.mime_types, resp->content_type))
		return -2;

	// do not save into directories
	fname_length = strlen(fname);
	if (fname[fname_length - 1] == '/') {
		debug_printf("not saved '%s' (file is a directory)\n", fname);
		return -1;
	}

	// - optimistic approach expects data being written without error
	// - to be Wget compatible: quota_modify_read() returns old quota value
	old_quota = quota_modify_read(config.save_headers ? resp->header->length : 0);

	if (config.quota && old_quota >= config.quota) {
		debug_printf("not saved '%s' (quota of %lld reached)\n", fname, config.quota);
		return -1;
	}

	if (fname == config.output_document) {
		// <fname> can only be NULL if config.delete_after is set
		if (!strcmp(fname, "-")) {
			if (config.save_headers) {
				size_t rc = safe_write(1, resp->header->data, resp->header->length);
				if (rc == SAFE_WRITE_ERROR) {
					error_printf(_("Failed to write to STDOUT (%zu, errno=%d)\n"), rc, errno);
					set_exit_status(WG_EXIT_STATUS_IO);
				}
			}

			return dup (1);
		}

		if (config.delete_after) {
			debug_printf("not saved '%s' (--delete-after)\n", fname);
			return -2;
		}

#ifdef _WIN32
		if (!wget_strcasecmp_ascii(fname, "NUL")) {
			// skip saving to NUL device, also suppresses error message from setting file date
			return -2;
		}
#endif

		// Gnulib accepts the /dev/null syntax on Windows too.
		if (!strcmp(fname, "/dev/null")) {
			// skip saving to /dev/null device, also suppresses error message from setting file date
			return -2;
		}

		flag = O_APPEND;
	}

	if (config.adjust_extension && resp->content_type) {
		const char *ext;

		if (!wget_strcasecmp_ascii(resp->content_type, "text/html") || !wget_strcasecmp_ascii(resp->content_type, "application/xhtml+xml")) {
			ext = ".html";
		} else if (!wget_strcasecmp_ascii(resp->content_type, "text/css")) {
			ext = ".css";
		} else if (!wget_strcasecmp_ascii(resp->content_type, "application/atom+xml")) {
			ext = ".atom";
		} else if (!wget_strcasecmp_ascii(resp->content_type, "application/rss+xml")) {
			ext = ".rss";
		} else
			ext = NULL;

		if (ext) {
			size_t ext_length = strlen(ext);

			if (fname_length >= ext_length && wget_strcasecmp_ascii(fname + fname_length - ext_length, ext)) {
				alloced_fname = wget_malloc(fname_length + ext_length + 1);
				memcpy(alloced_fname, fname, fname_length);
				memcpy(alloced_fname + fname_length, ext, ext_length + 1);
				fname = alloced_fname;
			}
		}
	}

	if (! ignore_patterns) {
		if ((config.accept_patterns && !in_pattern_list(config.accept_patterns, fname))
				|| (config.accept_regex && !regex_match(fname, config.accept_regex)))
		{
			debug_printf("not saved '%s' (doesn't match accept pattern)\n", fname);
			xfree(alloced_fname);
			return -2;
		}

		if ((config.reject_patterns && in_pattern_list(config.reject_patterns, fname))
				|| (config.reject_regex && regex_match(fname, config.reject_regex)))
		{
			debug_printf("not saved '%s' (matches reject pattern)\n", fname);
			xfree(alloced_fname);
			return -2;
		}

		if (config.exclude_directories && in_directory_pattern_list(config.exclude_directories, path)) {
			debug_printf("not saved '%s' (directory excluded)\n", path);
			xfree(alloced_fname);
			return -2;
		}
	}

	wget_thread_mutex_lock(savefile_mutex);

	fname_length += 16;

	if (config.timestamping) {
		if (oflag == O_TRUNC)
			flag = O_TRUNC;
	} else if (!config.clobber || (config.recursive && config.directories)) {
		if (oflag == O_TRUNC && (!(config.recursive && config.directories) || (config.page_requisites && !config.clobber))) {
			flag = O_EXCL;
		}
	} else if (flag != O_APPEND) {
		// wget compatibility: "clobber" means generating of .x files
		multiple = 1;
		flag = O_EXCL;

		if (config.backups) {
			char src[fname_length + 1], dst[fname_length + 1];

			for (int it = config.backups; it > 0; it--) {
				if (it > 1)
					wget_snprintf(src, sizeof(src), "%s.%d", fname, it - 1);
				else
					wget_strscpy(src, fname, sizeof(src));
				wget_snprintf(dst, sizeof(dst), "%s.%d", fname, it);

				if (rename(src, dst) == -1 && errno != ENOENT)
					error_printf(_("Failed to rename %s to %s (errno=%d)\n"), src, dst, errno);
			}
		}
	}

	// create the complete directory path
	mkdir_path((char *) fname, true);

	char unique[fname_length + 1];
	*unique = 0;

	// Load partial content
	if (partial_content) {
		long long size = get_file_size(unique[0] ? unique : fname);
		if (size > 0) {
			fd = _open_unique(fname, O_RDONLY | O_BINARY, 0, multiple, unique, sizeof(unique));
			if (fd >= 0) {
				size_t rc;
				if ((unsigned long long) size > max_partial_content)
					size = max_partial_content;
				wget_buffer_memset_append(partial_content, 0, size);
				rc = safe_read(fd, partial_content->data, size);
				if (rc == SAFE_READ_ERROR || (long long) rc != size) {
					error_printf(_("Failed to load partial content from '%s' (errno=%d): %s\n"),
						fname, errno, strerror(errno));
					set_exit_status(WG_EXIT_STATUS_IO);
				}
				close(fd);
			} else {
				error_printf(_("Failed to load partial content from '%s' (errno=%d): %s\n"),
					fname, errno, strerror(errno));
				set_exit_status(WG_EXIT_STATUS_IO);
			}
		}
	}

	if (config.unlink && flag == O_TRUNC) {
		if (unlink(fname) < 0 && errno != ENOENT) {
			error_printf(_("Failed to unlink '%s' (errno=%d): %s\n"),
				fname, errno, strerror(errno));
			set_exit_status(WG_EXIT_STATUS_IO);
			return -1;
		}
	}

	fd = _open_unique(fname, O_WRONLY | flag | O_CREAT | O_NONBLOCK | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
		multiple, unique, sizeof(unique));
	// debug_printf("1 fd=%d flag=%02x (%02x %02x %02x) errno=%d %s\n",fd,flag,O_EXCL,O_TRUNC,O_APPEND,errno,fname);
	// Store the "actual" file name (with any extensions that were added present)
	wget_asprintf(actual_file_name, "%s", unique[0] ? unique : fname);

	if (fd >= 0) {
		ssize_t rc;

		info_printf(_("Saving '%s'\n"), *actual_file_name);

		if (config.save_headers) {
			if ((rc = write(fd, resp->header->data, resp->header->length)) != (ssize_t)resp->header->length) {
				error_printf(_("Failed to write file %s (%zd, errno=%d)\n"), *actual_file_name, rc, errno);
				set_exit_status(WG_EXIT_STATUS_IO);
			}
		}
		// TODO SAVE UNIQUE-NESS
	} else {
		if (fd == -1) {
			if (errno == EEXIST) {
				error_printf(_("File '%s' already there; not retrieving.\n"), fname);

				if (config.page_requisites && !config.clobber) {
					parse_localfile(job, job->local_filename, config.remote_encoding, resp->content_type, job->iri);
				}
			} else if (errno == EISDIR)
				info_printf(_("Directory / file name clash - not saving '%s'\n"), fname);
			else {
				error_printf(_("Failed to open '%s' (errno=%d): %s\n"), fname, errno, strerror(errno));
				set_exit_status(WG_EXIT_STATUS_IO);
			}
		}
	}

	if (config.xattr) {
		FILE *fp;
		if ((fp = fopen(*actual_file_name, "ab"))) {
			set_file_metadata(uri, original_url, resp->content_type, resp->content_type_encoding, resp->last_modified ? resp->last_modified - 1 : 0, fp);
			fclose(fp);
		} else {
			error_printf(_("Failed to save extended attribute %s\n"), *actual_file_name);
			set_exit_status(WG_EXIT_STATUS_IO);
		}
	}

	wget_thread_mutex_unlock(savefile_mutex);

	xfree(alloced_fname);
	return fd;
}

// context used for header and body callback
struct _body_callback_context {
	JOB *job;
	wget_buffer_t *body;
	uint64_t max_memory;
	uint64_t length;
	int outfd;
	int progress_slot;
	long long limit_debt_bytes;
	long long limit_prev_time_ms;
};

static int _get_header(wget_http_response_t *resp, void *context)
{
	struct _body_callback_context *ctx = (struct _body_callback_context *)context;
	PART *part;
	const char *dest = NULL, *name;
	int ret = 0;
#ifdef _WIN32
	char *fname_allocated = NULL;
#endif

	bool metalink = config.metalink && resp->content_type
	    && (!wget_strcasecmp_ascii(resp->content_type, "application/metalink4+xml") ||
		!wget_strcasecmp_ascii(resp->content_type, "application/metalink+xml"));

	if (ctx->job->head_first || (config.metalink && metalink)) {
		name = ctx->job->local_filename;
	} else if ((part = ctx->job->part)) {
		name = ctx->job->metalink->name;
		ctx->outfd = open(ctx->job->metalink->name, O_WRONLY | O_CREAT | O_NONBLOCK | O_BINARY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (ctx->outfd == -1) {
			set_exit_status(WG_EXIT_STATUS_IO);
			ret = -1;
			goto out;
		}
		if (lseek(ctx->outfd, part->position, SEEK_SET) == (off_t) -1) {
			close(ctx->outfd);
			set_exit_status(WG_EXIT_STATUS_IO);
			ret = -1;
			goto out;
		}
	}
	else if (config.content_disposition && resp->content_filename) {
#ifdef _WIN32
		fname_allocated = wget_malloc(strlen(resp->content_filename) * 3 + 1);
		name = dest = wget_restrict_file_name(resp->content_filename, fname_allocated, WGET_RESTRICT_NAMES_WINDOWS);
		if (name != fname_allocated)
			xfree(fname_allocated);
#else
		name = dest = resp->content_filename;
#endif
	} else
		name = dest = config.output_document ? config.output_document : ctx->job->local_filename;

	if (dest
		&& ((config.save_content_on && check_status_code_list(config.save_content_on, resp->code))
		|| (!config.save_content_on
			&& (resp->code == 200 || resp->code == 206 || config.content_on_error)))) {

		// Job re-use?
		xfree(ctx->job->sig_filename);

		ctx->outfd = _prepare_file(resp, dest,
			resp->code == 206 ? O_APPEND : O_TRUNC,
			ctx->job->iri,
			ctx->job->original_url,
			ctx->job->ignore_patterns,
			resp->code == 206 ? ctx->body : NULL,
			ctx->max_memory,
			&ctx->job->sig_filename,
			ctx->job->iri->path);

		if (ctx->outfd == -1)
			ret = -1;
	}

//	info_printf("Opened %d\n", ctx->outfd);

#ifdef _WIN32
	xfree(fname_allocated);
#endif

out:
	if (config.progress) {
		const char *filename = NULL;

		if (!name) {
			filename = _get_local_filename(ctx->job->iri);

			if ((name = strrchr(filename, '/')))
				name += 1;
			else
				name = filename;
		}

		if (!wget_strcasecmp_ascii(resp->req->method, "HEAD")) {
			bar_slot_begin(ctx->progress_slot, name, 0, resp->header->length);
			bar_set_downloaded(ctx->progress_slot, resp->header->length);
		} else {
			bar_slot_begin(ctx->progress_slot, name, ((resp->code == 200 || resp->code == 206) ? 1 : 0), resp->content_length);
		}

		xfree(filename);
	}

	return ret;
}

// Search function for --save-content-on=. Return 0 if content won't be downloaded and 1 if it will.
static bool check_status_code_list(wget_vector_t *list, uint16_t status)
{
	char result = 0;
	char key[6];

	wget_snprintf(key, sizeof(key), "%hu", status);

	for (int i = 0; i < wget_vector_size(list); i++) {
		char *entry = wget_vector_get(list, i);
		bool exclude = (*entry == '!');

		entry += exclude;

		if (strpbrk(entry, "*") && !fnmatch(entry, key, FNM_CASEFOLD))
			result = !exclude;
		else if (!wget_strcasecmp(entry, key))
			result = !exclude;
	}

	return result;
}

// Sleep after reading to slow down the transfer rate
// Based on rsync's bandwidth limit implementation (see io.c:sleep_for_bwlimit)
static void limit_transfer_rate(struct _body_callback_context *ctx, size_t read_bytes)
{
	long sleep_ms;
	long elapsed_ms;
	long long curr_time_ms;
	long long thread_rate_limit;

	if (nthreads > 1) {
		// Split the limit rate evenly across the threads
		thread_rate_limit = config.limit_rate / nthreads;
	} else {
		thread_rate_limit = config.limit_rate;
	}

	ctx->limit_debt_bytes += (long long) read_bytes;

	curr_time_ms = wget_get_timemillis();
	if (ctx->limit_prev_time_ms != 0) {
		elapsed_ms = (curr_time_ms - ctx->limit_prev_time_ms);
		ctx->limit_debt_bytes -= elapsed_ms * thread_rate_limit / 1000;
	}

	if (ctx->limit_debt_bytes <= 0) {
		ctx->limit_debt_bytes = 0;
		ctx->limit_prev_time_ms = curr_time_ms;
		return;
	}

	sleep_ms = ctx->limit_debt_bytes * 1000 / thread_rate_limit;
	wget_millisleep(sleep_ms);

	ctx->limit_prev_time_ms = wget_get_timemillis();
	elapsed_ms = ctx->limit_prev_time_ms - curr_time_ms;
	ctx->limit_debt_bytes = (sleep_ms - elapsed_ms) * thread_rate_limit / 1000;
}


static int _get_body(wget_http_response_t *resp, void *context, const char *data, size_t length)
{
	struct _body_callback_context *ctx = (struct _body_callback_context *)context;

	if (ctx->length == 0) {
		// first call to _get_body
		if (config.server_response)
			info_printf(_("# got header %zu bytes:\n%s\n"), resp->header->length, resp->header->data);
	}

	ctx->length += length;

	if (ctx->outfd >= 0) {
		size_t written = safe_write(ctx->outfd, data, length);

		if (written == SAFE_WRITE_ERROR) {
#if EAGAIN != EWOULDBLOCK
			if ((errno == EAGAIN || errno == EWOULDBLOCK) && !terminate) {
#else
			if (errno == EAGAIN && !terminate) {
#endif
				if (wget_ready_2_write(ctx->outfd, 1000) > 0) {
					written = safe_write(ctx->outfd, data, length);
				}
			}
		}

		if (written == SAFE_WRITE_ERROR) {
			if (!terminate)
				debug_printf("Failed to write errno=%d\n", errno);
			set_exit_status(WG_EXIT_STATUS_IO);
			return -1;
		}
	}

	if (ctx->max_memory == 0 || ctx->length < ctx->max_memory)
		wget_buffer_memcat(ctx->body, data, length); // append new data to body

	if (config.progress) {
		bar_set_downloaded(ctx->progress_slot, resp->cur_downloaded - resp->accounted_for);
		resp->accounted_for = resp->cur_downloaded;
	}

	if (config.limit_rate)
		limit_transfer_rate(ctx, length);

	return 0;
}

static void _add_authorize_header(
	wget_http_request_t *req,
	wget_vector_t *challenges,
	const char *username, const char *password, int proxied)
{
	// There might be more than one challenge, we could select the most secure one.
	// Prefer 'Digest' over 'Basic'
	// the following adds an Authorization: or Proxy-Authorization HTTP header
	wget_http_challenge_t *selected_challenge = NULL;

	for (int it = 0; it < wget_vector_size(challenges); it++) {
		wget_http_challenge_t *challenge = wget_vector_get(challenges, it);

		if (!wget_strcasecmp_ascii(challenge->auth_scheme, "digest")) {
			selected_challenge = challenge;
			break;
		}
		else if (!wget_strcasecmp_ascii(challenge->auth_scheme, "basic")) {
			if (!selected_challenge)
				selected_challenge = challenge;
		}
	}

	if (selected_challenge) {
		if (username) {
			wget_http_add_credentials(req, selected_challenge, username, password, proxied);
		} else if (config.netrc_file) {
			wget_thread_mutex_lock(netrc_mutex);
			if (!config.netrc_db) {
				config.netrc_db = wget_netrc_db_init(NULL);
				wget_netrc_db_load(config.netrc_db, config.netrc_file);
			}
			wget_thread_mutex_unlock(netrc_mutex);

			wget_netrc_t *netrc = wget_netrc_get(config.netrc_db, req->esc_host.data);
			if (!netrc)
				netrc = wget_netrc_get(config.netrc_db, "default");

			if (netrc) {
				wget_http_add_credentials(req, selected_challenge, netrc->login, netrc->password, proxied);
			} else {
				wget_http_add_credentials(req, selected_challenge, username, password, proxied);
			}
		} else {
			wget_http_add_credentials(req, selected_challenge, username, password, proxied);
		}
	}
}

static wget_http_request_t *http_create_request(wget_iri_t *iri, JOB *job)
{
	wget_http_request_t *req;
	wget_buffer_t buf;
	char sbuf[256];
	const char *method;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	if (job->head_first) {
		method = "HEAD";
	} else {
		if (config.post_data || config.post_file)
			method = "POST";
		else
			method = "GET";
	}

	if (!(req = wget_http_create_request(iri, method)))
		return req;

	if (config.continue_download || config.timestamping) {
		const char *local_filename = config.output_document ? config.output_document : job->local_filename;

		/* We never want to continue the robots job. Always grab a fresh copy
		 * from the server. */
		if (job->robotstxt == true) {
			unlink(local_filename);
		}

		if (config.continue_download) {
			long long file_size = get_file_size(local_filename);
			if (file_size > 0)
				wget_http_add_header_printf(req, "Range", "bytes=%lld-", file_size);
		}

		if (config.timestamping) {
			bool found_mtime = 0;
			time_t mtime = 0;
			FILE *fp;

			// see if we stored the server timestamp before
			if ((fp = fopen(local_filename, "r"))) {
				char tbuf[32];
				if (read_xattr_metadata("user.last_modified", tbuf, sizeof(tbuf), fileno(fp)) > 0) {
					mtime = (time_t) atoll(tbuf);
					found_mtime = 1;
				}
				fclose(fp);
			}

			if (!found_mtime)
				mtime = get_file_mtime(local_filename);

			if (mtime) {
				char http_date[32];

				wget_http_print_date(mtime, http_date, sizeof(http_date));
				wget_http_add_header(req, "If-Modified-Since", http_date);
			}
		}

	}

	// 20.06.2012: www.google.de only sends gzip responses with one of the
	// following header lines in the request.
	// User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.5) Gecko/20100101 Firefox/10.0.5 Iceweasel/10.0.5
	// User-Agent: Mozilla/5.0 (X11; Linux) KHTML/4.8.3 (like Gecko) Konqueror/4.8
	// User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.34 Safari/536.11
	// User-Agent: Opera/9.80 (X11; Linux x86_64; U; en) Presto/2.10.289 Version/12.00
	// User-Agent: Wget/1.13.4 (linux-gnu)
	//
	// Accept: prefer XML over HTML
	/*				"Accept-Encoding: gzip\r\n"\
	"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.5) Gecko/20100101 Firefox/10.0.5 Iceweasel/10.0.5\r\n"\
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8\r\n"
	"Accept-Language: en-us,en;q=0.5\r\n");
	 */

	wget_buffer_reset(&buf);

	// if compression is specified
	if (config.compression) {
		for (int it = 0; it < config.compression_methods[wget_content_encoding_max]; it++) {
			const char *encoding_method = wget_content_encoding_to_name(config.compression_methods[it]);
			if (buf.length)
				wget_buffer_strcat(&buf, ", ");
			wget_buffer_strcat(&buf, encoding_method);
		}

		if (buf.length)
			wget_http_add_header(req, "Accept-Encoding", buf.data);
	}

	// no valid types provided or just default Accept-Encoding
	if ((!config.no_compression && !config.compression) || (config.compression && !buf.length)) {
#ifdef WITH_ZLIB
		wget_buffer_strcat(&buf, buf.length ? ", gzip, deflate" : "gzip, deflate");
#endif
#ifdef WITH_BZIP2
		wget_buffer_strcat(&buf, buf.length ? ", bzip2" : "bzip2");
#endif
#ifdef WITH_LZMA
		wget_buffer_strcat(&buf, buf.length ? ", xz, lzma" : "xz, lzma");
#endif
#ifdef WITH_BROTLIDEC
		wget_buffer_strcat(&buf, buf.length ? ", br" : "br");
#endif
#ifdef WITH_ZSTD
		wget_buffer_strcat(&buf, buf.length ? ", zstd" : "zstd");
#endif

		if (!buf.length)
			wget_buffer_strcat(&buf, "identity");

		wget_http_add_header(req, "Accept-Encoding", buf.data);
	}

	wget_http_add_header(req, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");

//	if (config.spider && !config.recursive)
//		http_add_header_if_modified_since(time(NULL));
//		http_add_header(req, "If-Modified-Since", "Wed, 29 Aug 2012 00:00:00 GMT");

	if (config.user_agent)
		wget_http_add_header(req, "User-Agent", config.user_agent);

	if (config.keep_alive)
		wget_http_add_header(req, "Connection", "keep-alive");

	if (!config.cache) {
		// no-cache means a server/proxy MUST NOT serve cached data
		wget_http_add_header(req, "Cache-Control", "no-cache");

		// Some older proxies just understand the Pragma: header
		wget_http_add_header(req, "Pragma", "no-cache");
	}

	if (config.referer)
		wget_http_add_header(req, "Referer", config.referer);
	else if (job->referer) {
		wget_iri_t *referer = job->referer;

		wget_buffer_strcpy(&buf, referer->scheme);
		wget_buffer_memcat(&buf, "://", 3);
		wget_buffer_strcat(&buf, referer->host);
		if (referer->port_given)
			wget_buffer_printf_append(&buf, ":%hu", referer->port);
		wget_buffer_memcat(&buf, "/", 1);
		wget_iri_get_escaped_resource(referer, &buf);

		wget_http_add_header(req, "Referer", buf.data);
	}

	if (job->challenges) {
		_add_authorize_header(req, job->challenges, config.http_username, config.http_password, 0);
	} else if (job->proxy_challenges) {
		_add_authorize_header(req, job->proxy_challenges, config.http_proxy_username, config.http_proxy_password, 1);
	}

	if (job->part)
		wget_http_add_header_printf(req, "Range", "bytes=%llu-%llu",
			(unsigned long long) job->part->position, (unsigned long long) job->part->position + job->part->length - 1);

	// add cookies
	if (config.cookies) {
		const char *cookie_string;

		if ((cookie_string = wget_cookie_create_request_header(config.cookie_db, iri))) {
			wget_http_add_header(req, "Cookie", cookie_string);
			xfree(cookie_string);
		}
	}

	if (config.headers) {
		for (int i = 0; i < wget_vector_size(config.headers); i++) {
			wget_http_header_param_t *param = wget_vector_get(config.headers, i);
			char replaced = 0;

			// replace wget's HTTP headers by user-provided headers, except Cookie (which will just be added))
			if (wget_strcasecmp_ascii(param->name, "Cookie")) {
				for (int j = 0; j < wget_vector_size(req->headers); j++) {
					wget_http_header_param_t *h = wget_vector_get(req->headers, j);

					if (!wget_strcasecmp_ascii(param->name, h->name)) {
						wget_http_free_param(h);
						h->name = wget_strdup(param->name);
						h->value = wget_strdup(param->value);
						replaced = 1;
					}
				}
			}

			if (!replaced)
				wget_http_add_header_param(req, param);
		}
	}

	if (config.post_data) {
		size_t length = strlen(config.post_data);

		wget_http_request_set_body(req, "application/x-www-form-urlencoded", wget_memdup(config.post_data, length), length);
	} else if (config.post_file) {
		size_t length;
		char *data;

		if ((data = wget_read_file(config.post_file, &length))) {
			wget_http_request_set_body(req, "application/x-www-form-urlencoded", data, length);
		} else {
			wget_http_free_request(&req);
		}
	}

	wget_buffer_deinit(&buf);

	return req;
}

int http_send_request(wget_iri_t *iri, wget_iri_t *original_url, DOWNLOADER *downloader)
{
	wget_http_connection_t *conn = downloader->conn;

	JOB *job = downloader->job;
	int rc;

	if (job->head_first) {
		// In spider mode, we first make a HEAD request.
		// If the Content-Type header gives us not a parseable type, we are done.
		print_status(downloader, "[%d] Checking '%s' ...\n", downloader->id, iri->uri);
	} else {
		if (job->part)
			print_status(downloader, "downloading part %d/%d (%lld-%lld) %s from %s\n",
				job->part->id, wget_vector_size(job->parts),
				(long long)job->part->position, (long long)(job->part->position + job->part->length - 1),
				job->metalink->name, iri->host);
		else if (config.progress)
			bar_print(downloader->id, iri->uri);
		else
			print_status(downloader, "[%d] Downloading '%s' ...\n", downloader->id, iri->uri);
	}

	wget_http_request_t *req = http_create_request(iri, downloader->job);

	if (!req)
		return WGET_E_UNKNOWN;

	wget_http_request_set_ptr(req, WGET_HTTP_USER_DATA, downloader->job);

	if ((rc = wget_http_send_request(conn, req))) {
		wget_http_free_request(&req);
		return rc;
	}

	struct _body_callback_context *context = wget_calloc(1, sizeof(struct _body_callback_context));

	context->job = downloader->job;
	context->max_memory = downloader->job->part ? 0 : ((uint64_t) 10) * (1 << 20);
	context->outfd = -1;
	context->body = wget_buffer_alloc(102400);
	context->length = 0;
	context->progress_slot = downloader->id;
	context->job->original_url = original_url;
	context->limit_debt_bytes = 0;
	context->limit_prev_time_ms = wget_get_timemillis();

	// set callback functions
	wget_http_request_set_header_cb(req, _get_header, context);
	wget_http_request_set_body_cb(req, _get_body, context);

	// keep the received response header in 'resp->header'
	wget_http_request_set_int(req, WGET_HTTP_RESPONSE_KEEPHEADER, config.save_headers || config.server_response || (config.progress && config.spider));

	return WGET_E_SUCCESS;
}

wget_http_response_t *http_receive_response(wget_http_connection_t *conn)
{
	wget_http_response_t *resp = wget_http_get_response_cb(conn);

	if (!resp)
		return NULL;

	struct _body_callback_context *context = resp->req->body_user_data;

	resp->body = context->body;

	if (context->outfd >= 0) {
		if (resp->last_modified) {
			/* If program was aborted, we store file times one second less than the server time.
			 * So a later download with -N would start over instead of leaving incomplete data.
			 * Or a later download with -c -N would continue with a IF-MODIFIED-SINCE: HTTP header. */
			if (config.xattr && !terminate)
				write_xattr_last_modified(resp->last_modified, context->outfd);

			set_file_mtime(context->outfd, resp->last_modified - terminate);
		}

		if (config.fsync_policy) {
			if (fsync(context->outfd) < 0 && errno == EIO) {
				error_printf(_("Failed to fsync errno=%d\n"), errno);
				set_exit_status(WG_EXIT_STATUS_IO);
			}
		}

		close(context->outfd);
		context->outfd = -1;
	}

	if (config.progress)
		bar_slot_deregister(context->progress_slot);

	xfree(context);

	return resp;
}

#ifdef USE_XATTR

static int write_xattr_metadata(const char *name, const char *value, int fd)
{
	if (!(name && value && fd >= 0))
		return -1;

	int rc = fsetxattr(fd, name, value, strlen(value), 0) < 0 ? -1 : 0;

	if (rc)
		debug_printf("Failed to set xattr %s.\n", name);

	return rc;
}

// returns the length of value (which is a 0-terminated string) or -1 on error
static int read_xattr_metadata(const char *name, char *value, size_t size, int fd)
{
	if (!(name && value && size && fd >= 0))
		return -1;

	int rc = fgetxattr(fd, name, value, size - 1);
	if (rc < 0)
		return -1;

	// just to make sure...
	if (rc >= (int) size)
		rc = size - 1;

	value[rc] = 0;
	return rc;
}

static int write_xattr_last_modified(time_t last_modified, int fd)
{
	char tbuf[32];

	if (fd < 0)
		return -1;

	wget_snprintf(tbuf, sizeof(tbuf), "%lld", (long long) last_modified);
	return write_xattr_metadata("user.last_modified", tbuf, fd);
}

#else /* USE_XATTR */

static int write_xattr_metadata(const char *name, const char *value, int fd)
{
	(void)name;
	(void)value;
	(void)fd;

	return -1;
}

static int read_xattr_metadata(const char *name, char *value, size_t size, int fd)
{
	(void)name;
	(void)value;
	(void)size;
	(void)fd;

	return -1;
}

static int write_xattr_last_modified(time_t last_modified, int fd)
{
	(void)last_modified;
	(void)fd;

	return -1;
}
#endif /* USE_XATTR */

/* Store metadata name/value attributes against fp. */
static int set_file_metadata(wget_iri_t *origin_iri, wget_iri_t *referrer_iri,
					  const char *mime_type, const char *charset,
					  time_t last_modified, FILE *fp)
{
	int fd;

	/* Save metadata about where the file came from (requested, final URLs) to
	 * user POSIX Extended Attributes of retrieved file.
	 *
	 * For more details about the user namespace see
	 * [http://freedesktop.org/wiki/CommonExtendedAttributes] and
	 * [http://0pointer.de/lennart/projects/mod_mime_xattr/].
	 */
	if (!origin_iri || !fp)
		return -1;

	if ((fd = fileno(fp)) < 0)
		return -1;

	if (write_xattr_metadata("user.mime_type", mime_type, fd) < 0 && errno == ENOTSUP)
		return -1; // give up early if file system doesn't support extended attributes

	write_xattr_metadata("user.charset", charset, fd);

	char sbuf[256];
	wget_buffer_t buf;
	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	wget_buffer_printf(&buf, "%s/", wget_iri_get_connection_part(origin_iri));
	wget_iri_get_escaped_resource(origin_iri, &buf);

	write_xattr_metadata("user.xdg.origin.url", buf.data, fd);

	wget_buffer_deinit(&buf);

	write_xattr_metadata("user.xdg.referrer.url", wget_iri_get_connection_part(referrer_iri), fd);

	return write_xattr_last_modified(last_modified, fd);
}

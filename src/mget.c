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
 * Main file
 *
 * Changelog
 * 07.04.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>

#include <libmget.h>

#include "mget.h"
#include "log.h"
#include "job.h"
#include "printf.h"
#include "options.h"
#include "metalink.h"
#include "blacklist.h"

typedef struct {
	mget_thread_t
		tid;
	JOB
		*job;
	PART
		*part;
	MGET_HTTP_CONNECTION
		*conn;
	char
		*buf;
	size_t
		bufsize;
	int
		id;
	mget_thread_cond_t
		cond;
} DOWNLOADER;

//static HTTP_RESPONSE
//	*http_get_uri(const char *uri);
static void
	download_part(DOWNLOADER *downloader),
	save_file(MGET_HTTP_RESPONSE *resp, const char *fname),
	append_file(MGET_HTTP_RESPONSE *resp, const char *fname),
	html_parse(JOB *job, int level, const char *data, const char *encoding, MGET_IRI *iri),
	html_parse_localfile(JOB *job, int level, const char *fname, const char *encoding, MGET_IRI *iri),
	css_parse(JOB *job, const char *data, const char *encoding, MGET_IRI *iri),
	css_parse_localfile(JOB *job, const char *fname, const char *encoding, MGET_IRI *iri);
MGET_HTTP_RESPONSE
	*http_get(MGET_IRI *iri, PART *part, DOWNLOADER *downloader);

static DOWNLOADER
	*downloaders;
static void
	*downloader_thread(void *p);
long long
	quota;
static int
	terminate;

// generate the local filename corresponding to an URI
// respect the following options:
// --restrict-file-names (unix,windows,nocontrol,ascii,lowercase,uppercase)
// -nd / --no-directories
// -x / --force-directories
// -nH / --no-host-directories
// --protocol-directories
// --cut-dirs=number
// -P / --directory-prefix=prefix

static const char * G_GNUC_MGET_NONNULL_ALL get_local_filename(MGET_IRI *iri)
{
	mget_buffer_t buf;
	const char *fname;
	int directories;

	if (config.spider || config.output_document)
		return NULL;

	directories = !!config.recursive;

	if (config.directories == 0)
		directories = 0;

	if (config.force_directories == 1)
		directories = 1;

	mget_buffer_init(&buf, NULL, 256);

	if (config.directory_prefix && *config.directory_prefix) {
		mget_buffer_strcat(&buf, config.directory_prefix);
		mget_buffer_memcat(&buf, "/", 1);
	}

	if (directories) {
		if (config.protocol_directories && iri->scheme && *iri->scheme) {
			mget_buffer_strcat(&buf, iri->scheme);
			mget_buffer_memcat(&buf, "/", 1);
		}
		if (config.host_directories && iri->host && *iri->host) {
			mget_iri_get_escaped_host(iri, &buf);
			// buffer_memcat(&buf, "/", 1);
		}

		if (config.cut_directories) {
			// cut directories
			mget_buffer_t path_buf;
			const char *p;
			int n;

			mget_buffer_init(&path_buf, (char[256]){}, 256);
			mget_iri_get_escaped_path(iri, &path_buf);

			for (n = 0, p = path_buf.data; n < config.cut_directories && p; n++) {
				p = strchr(*p =='/' ? p + 1 : p, '/');
			}
			if (!p) {
				// we can't strip this many path elements, just use the filename
				p = strrchr(path_buf.data, '/');
				if (!p) {
					p = path_buf.data;
					if (*p != '/')
						mget_buffer_memcat(&buf, "/", 1);
					mget_buffer_strcat(&buf, p);
				}
			}

			mget_buffer_deinit(&path_buf);
		} else {
			mget_iri_get_escaped_path(iri, &buf);
		}

		fname = mget_iri_get_escaped_query(iri, &buf);
	} else {
		fname = mget_iri_get_escaped_file(iri, &buf);
	}

	// create the complete path
	if (*fname) {
		const char *p1, *p2;

		for (p1 = fname; *p1 && (p2 = strchr(p1, '/')); p1 = p2 + 1) {
			*(char *)p2 = 0; // replace path separator

			// relative paths should have been normalized earlier,
			// but for security reasons, don't trust myself...
			if (*p1 == '.' && p1[1] == '.')
				error_printf_exit(_("Internal error: Unexpected relative path: '%s'\n"), fname);

			if (mkdir(fname, 0755) != 0 && errno != EEXIST) {
				error_printf(_("Failed to make directory '%s'\n"), fname);
				*(char *)p2 = '/'; // restore path separator
				return fname;
			} else debug_printf("mkdir %s\n", fname);

			*(char *)p2 = '/'; // restore path separator
		}
	}

	if (config.delete_after) {
		mget_buffer_deinit(&buf);
		fname = NULL;
	} else
		debug_printf("local filename = '%s'\n", fname);

	return fname;
}

// Since quota may change at any time in a threaded environment,
// we have to modify and check the quota in one (protected) step.
static long long quota_modify_read(size_t nbytes)
{
	static mget_thread_mutex_t
		mutex = MGET_THREAD_MUTEX_INITIALIZER;
	size_t old_quota;

	mget_thread_mutex_lock(&mutex);
	old_quota = quota;
	quota += nbytes;
	mget_thread_mutex_unlock(&mutex);

	return old_quota;
}

// everything host/domain specific should go here
typedef struct {
	const char
		*scheme,
		*host;
	unsigned int
		got_robots; // if /robots.txt has been fetched
} HOST;

static MGET_HASHMAP
	*hosts;
static mget_thread_mutex_t
	hosts_mutex = MGET_THREAD_MUTEX_INITIALIZER;

static int _host_compare(const HOST *host1, const HOST *host2)
{
	int n;

	if (host1->scheme != host2->scheme)
		return host1->scheme < host2->scheme ? -1 : 1;

	// host is already lowercase, no need to call strcasecmp()
	if ((n = strcmp(host1->host, host2->host)))
		return n;

	return 0;
}

static unsigned int _host_hash(const HOST *host)
{
	unsigned int hash = 0; // use 0 as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	for (p = (unsigned char *)host->scheme; p && *p; p++)
		hash = hash * 101 + *p;

	for (p = (unsigned char *)host->host; p && *p; p++)
		hash = hash * 101 + *p;

	return hash;
}

static void hosts_add(MGET_IRI *iri)
{
	if (!iri)
		return;

	mget_thread_mutex_lock(&hosts_mutex);

	if (!hosts)
		hosts = mget_hashmap_create(16, -2, (unsigned int (*)(const void *))_host_hash, (int (*)(const void *, const void *))_host_compare);

	HOST *host = xcalloc(1,sizeof(HOST));
	host->scheme = iri->scheme;
	host->host = iri->host;

	if (!mget_hashmap_contains(hosts, host)) {
		// info_printf("Add to hosts: %s\n", hostname);
		mget_hashmap_put_noalloc(hosts, host, host);
	}

	mget_thread_mutex_unlock(&hosts_mutex);
}
/*
static int _free_host_entry(const char *name G_GNUC_MGET_UNUSED, HOST *host)
{
//	xfree(host->name);
	return 0;
}
*/
static void hosts_free(void)
{
	mget_thread_mutex_lock(&hosts_mutex);

	//	mget_hashmap_browse(hosts, (int(*)(const char *, const void *))_free_host_entry);
	mget_hashmap_free(&hosts);

	mget_thread_mutex_unlock(&hosts_mutex);
}

static mget_thread_mutex_t
	downloader_mutex = MGET_THREAD_MUTEX_INITIALIZER;

// Needs to be thread-save
static JOB *add_url_to_queue(const char *url, MGET_IRI *base, const char *encoding)
{
	MGET_IRI *iri;
	JOB *job;

	if (base) {
		mget_buffer_t buf;

		mget_buffer_init(&buf, (char[256]){}, 256);
		iri = mget_iri_parse(mget_iri_relative_to_abs(base, url, strlen(url), &buf), encoding);
		mget_buffer_deinit(&buf);
	} else {
		// no base and no buf: just check URL for being an absolute URI
		iri = mget_iri_parse(mget_iri_relative_to_abs(NULL, url, strlen(url), NULL), encoding);
	}

	if (!iri) {
		error_printf(_("Cannot resolve relative URI %s\n"), url);
		return NULL;
	}

	mget_thread_mutex_lock(&downloader_mutex);

	job = queue_add(blacklist_add(iri));

	if (job) {
		if (!config.output_document)
			job->local_filename = get_local_filename(job->iri);

		if (config.recursive && !config.span_hosts) {
			// only download content from hosts given on the command line or from input file
			if (!mget_stringmap_contains(config.exclude_domains, job->iri->host)) {
				mget_stringmap_put(config.domains, job->iri->host, NULL, 0);
			}

			hosts_add(job->iri);
		}
	}

	mget_thread_mutex_unlock(&downloader_mutex);

	return job;
}

// Needs to be thread-save
static void add_uri(JOB *job, const char *encoding, const char *uri, int redirection)
{
	JOB *new_job;
	MGET_IRI *iri;

	if (redirection) { // redirect
		if (config.max_redirect && job && job->redirection_level >= config.max_redirect) {
			return;
		}
	} else {
//		if (config.recursive) {
//			if (config.level && job->level >= config.level + config.page_requisites) {
//				continue;
//			}
//		}
	}

	iri = mget_iri_parse(uri, encoding);

	mget_thread_mutex_lock(&downloader_mutex);

	if (config.recursive && !config.span_hosts) {
		// only download content from given hosts
		if (!iri->host || !mget_stringmap_contains(config.domains, iri->host) || mget_stringmap_contains(config.exclude_domains, iri->host)) {
			mget_thread_mutex_unlock(&downloader_mutex);
			info_printf("URI '%s' not followed\n", iri->uri);
			mget_iri_free(&iri);
			return;
		}
	}

	if ((new_job = queue_add(blacklist_add(iri)))) {
		if (!config.output_document)
			new_job->local_filename = get_local_filename(new_job->iri);
		if (job) {
			if (redirection) {
				new_job->redirection_level = job->redirection_level + 1;
				new_job->referer = job->referer;
			} else {
				new_job->level = job->level + 1;
				new_job->referer = job->iri;
			}
		}
	}

	mget_thread_mutex_unlock(&downloader_mutex);
}

static void print_status(DOWNLOADER *downloader, const char *fmt, ...) G_GNUC_MGET_NONNULL_ALL G_GNUC_MGET_PRINTF_FORMAT(2,3);
static void print_status(DOWNLOADER *downloader G_GNUC_MGET_UNUSED, const char *fmt, ...)
{
	if (config.verbose) {
		va_list args;

		va_start(args, fmt);
		mget_info_vprintf(fmt, args);
		va_end(args);
	}
}

static void nop(int sig)
{
	if (sig == SIGTERM) {
		terminate = 1; // set global termination flag
	} else if (sig == SIGINT) {
		abort();
	}
}

static mget_thread_mutex_t
	main_mutex = MGET_THREAD_MUTEX_INITIALIZER;
static mget_thread_cond_t
	main_cond = MGET_THREAD_COND_INITIALIZER, // is signalled whenever a job is done
	worker_cond = MGET_THREAD_COND_INITIALIZER;  // is signalled whenever a job is added
static mget_thread_t
	input_tid;
static void
	*input_thread(void *p);

int main(int argc, const char *const *argv)
{
	int n, rc;
	size_t bufsize = 0;
	char *buf = NULL;
	struct sigaction sig_action;

#if ENABLE_NLS != 0
	#include <locale.h>
	setlocale(LC_ALL, "");
	bindtextdomain("mget", LOCALEDIR);
	textdomain("mget");
#endif

	/*
		char buf[20240];
		FILE *fp=fopen("styles.css","r");
		buf[fread(buf,1,20240,fp)]=0;
		fclose(fp);

		void css_dump(void *user_ctx, int flags, const char *dir, const char *attr, const char *val)
		{
	//		info_printf("\n%02X %s %s '%s'\n",flags,dir,attr,val);

	//		if (flags&CSS_FLG_SPACES) {
	//			info_printf("%s",val);
	//			return;
	//		}
			if (flags&CSS_FLG_ATTRIBUTE) {
				// check for url() attributes
				const char *p1=val, *p2;
				char quote;
				while (*p1) {
					if ((*p1=='u' || *p1=='U') && !strncasecmp(p1+1,"rl(",3)) {
						p1+=4;
						if (*p1=='\"' || *p1=='\'') {
							quote=*p1;
							p1++;
							for (p2=p1;*p2 && *p2!=quote;p2++);
						} else {
							for (p2=p1;*p2 && *p2!=')';p2++);
						}
						info_printf("*url = %.*s\n",(int)(p2-p1),p1);
					} else
						p1++;
				}

				info_printf("\t%s: %s;\n",attr,val);
				return;
			}
			if (flags&CSS_FLG_SELECTOR_BEGIN) {
				info_printf("%s {\n",val);
			}
			if (flags&CSS_FLG_SELECTOR_END) {
				info_printf("}\n");
			}
		}
		css_parse_buffer(buf,css_dump,NULL,0);
		return 0;

		char buf[20240];
		FILE *fp=fopen("index.html","r");
		buf[fread(buf,1,20240,fp)]=0;
		fclose(fp);

		void xml_dump(UNUSED void *user_ctx, int flags, const char *dir, const char *attr, const char *val)
		{
	//		info_printf("\n%02X %s %s '%s'\n",flags,dir,attr,val);

			if (flags&XML_FLG_BEGIN) {
				const char *p=*dir=='/'?strrchr(dir,'/'):dir;
				if (p) {
					if (*dir=='/') p++;
					if (flags==(XML_FLG_BEGIN|XML_FLG_END)) {
						info_printf("<%s/>",p);
						return;
					}
					info_printf("<%s",p);
				}
			}
			if (flags&XML_FLG_ATTRIBUTE) {
				if (val)
					info_printf(" %s=\"%s\"",attr,val);
				else
					info_printf(" %s",attr); // HTML bareword attribute
			}
			if (flags&XML_FLG_CLOSE) {
				info_printf(">");
			}
			if (flags&XML_FLG_CONTENT) {
				info_printf("%s",val);
			}
			if (flags&XML_FLG_END) {
				const char *p=*dir=='/'?strrchr(dir,'/'):dir;
				if (p) {
					if (*dir=='/') p++;
					info_printf("</%s>",p);
				}
			}

			if (flags==XML_FLG_COMMENT)
				info_printf("<!--%s-->",val);
			else if (flags==XML_FLG_PROCESSING)
				info_printf("<?%s?>",val);
			else if (flags==XML_FLG_SPECIAL)
				info_printf("<!%s>",val);
		}
		html_parse_buffer(buf,xml_dump,NULL,HTML_HINT_REMOVE_EMPTY_CONTENT);
	//	xml_parse_buffer(buf,xml_dump,NULL,0);
	//	html_parse_file("index.html",xml_dump,NULL,0);
		return 0;
	 */

	// need to set some signals
	memset(&sig_action, 0, sizeof(sig_action));

	sig_action.sa_sigaction = (void (*)(int, siginfo_t *, void *))SIG_IGN;
	sigaction(SIGPIPE, &sig_action, NULL); // this forces socket error return
	sig_action.sa_handler = nop;
	sigaction(SIGTERM, &sig_action, NULL);
	sigaction(SIGINT, &sig_action, NULL);

	n = init(argc, argv);

	for (; n < argc; n++) {
		add_url_to_queue(argv[n], config.base, config.local_encoding);
	}

	if (config.input_file) {
		if (config.force_html) {
			// read URLs from HTML file
			html_parse_localfile(NULL, 0, config.input_file, config.remote_encoding, config.base);
		}
		else if (config.force_css) {
			// read URLs from CSS file
			css_parse_localfile(NULL, config.input_file, config.remote_encoding, config.base);
		}
		else if (strcmp(config.input_file, "-")) {
			int fd;
			ssize_t len;

			// read URLs from input file
			if ((fd = open(config.input_file, O_RDONLY))) {
				while ((len = mget_fdgetline(&buf, &bufsize, fd)) > 0) {
					add_url_to_queue(buf, config.base, config.local_encoding);
				}
				close(fd);
			} else
				error_printf(_("Failed to open input file %s\n"), config.input_file);
		} else {
			if (isatty(STDIN_FILENO)) {
				ssize_t len;

				// read URLs from STDIN
				while ((len = mget_fdgetline(&buf, &bufsize, STDIN_FILENO)) >= 0) {
					add_url_to_queue(buf, config.base, config.local_encoding);
				}
			} else if ((rc = mget_thread_start(&input_tid, input_thread, NULL, 0)) != 0) {
				error_printf(_("Failed to start downloader, error %d\n"), rc);
			}
		} // else read later asynchronous and process each URL immediately
	}

	downloaders = xcalloc(config.num_threads, sizeof(DOWNLOADER));

	for (n = 0; n < config.num_threads; n++) {
		downloaders[n].id = n;
		mget_thread_cond_init(&worker_cond);

		// init thread attributes
		if ((rc = mget_thread_start(&downloaders[n].tid, downloader_thread, &downloaders[n], 0)) != 0) {
			error_printf(_("Failed to start downloader, error %d\n"), rc);
		}
	}

	mget_thread_mutex_lock(&main_mutex);
	while (!terminate) {
		// queue_print();
		if (queue_empty() && !input_tid) {
			break;
		}

		if (config.quota && quota >= config.quota) {
			info_printf(_("Quota of %llu bytes reached - stopping.\n"), config.quota);
			break;
		}

		// here we sit and wait for an event from our worker threads
		mget_thread_cond_wait(&main_cond, &main_mutex);
	}
	mget_thread_mutex_unlock(&main_mutex);

//	info_printf(_("Main done\n"));
	xfree(buf);

	// stop downloaders
	terminate=1;
	mget_thread_cond_signal(&worker_cond);

	for (n = 0; n < config.num_threads; n++) {
		//		struct timespec ts;
		//		clock_gettime(CLOCK_REALTIME, &ts);
		//		ts.tv_sec += 1;
		// if the thread is not detached, we have to call pthread_join()/pthread_timedjoin_np()
		// else we will have a huge memory leak
		//		if ((rc=pthread_timedjoin_np(downloader[n].tid, NULL, &ts))!=0)
		if ((rc = mget_thread_join(downloaders[n].tid)) != 0)
			error_printf(_("Failed to wait for downloader #%d (%d %d)\n"), n, rc, errno);
	}

	if (config.save_cookies)
		mget_cookie_save(config.save_cookies, config.keep_session_cookies);

	if (config.delete_after && config.output_document)
		unlink(config.output_document);

	if (config.debug)
		blacklist_print();

	// freeing to avoid disguising valgrind output
	mget_cookie_free_public_suffixes();
	mget_cookie_free_cookies();
	mget_ssl_deinit();
	queue_free();
	blacklist_free();
	hosts_free();
	xfree(downloaders);
	deinit();

	return EXIT_SUCCESS;
}

void *input_thread(void *p G_GNUC_MGET_UNUSED)
{
	ssize_t len;
	size_t bufsize = 0;
	char *buf = NULL;

	while ((len = mget_fdgetline(&buf, &bufsize, STDIN_FILENO)) >= 0) {
		add_url_to_queue(buf, config.base, config.local_encoding);
		mget_thread_cond_signal(&worker_cond);
	}

	// input closed, don't read from it any more
	debug_printf("input closed\n");
	input_tid = 0;
	return NULL;
}

void *downloader_thread(void *p)
{
	DOWNLOADER *downloader = p;
	MGET_HTTP_RESPONSE *resp = NULL;
	JOB *job;
	PART *part;

	downloader->tid = mget_thread_self(); // to avoid race condition

	mget_thread_mutex_lock(&main_mutex);

	while (!terminate) {
		if (queue_get(&downloader->job, &downloader->part) == 0) {
			// here we sit and wait for a job
			mget_thread_cond_wait(&worker_cond, &main_mutex);
			continue;
		}

		// hey, we got a job...
		mget_thread_mutex_unlock(&main_mutex);
		job = downloader->job;

		if ((part = downloader->part)) {
			// download metalink part
			download_part(downloader);
			if (part->done) {
				// check if all parts are done (downloaded + hash-checked)
				int all_done = 1, it;

				for (it = 0; it < mget_vector_size(job->parts); it++) {
					PART *part = mget_vector_get(job->parts, it);
					if (!part->done) {
						all_done = 0;
						break;
					}
				}

				// log_printf("all_done=%d\n",all_done);
				if (all_done && mget_vector_size(job->hashes) > 0) {
					// check integrity of complete file
					print_status(downloader, "%s checking...\n", job->name);
					job_validate_file(job);
					if (job->hash_ok) {
						debug_printf("checksum ok");
						queue_del(job);
						mget_thread_cond_signal(&main_cond);
					} else
						debug_printf("checksum failed");
					continue;
				}
			} else part->inuse = 0; // something was wrong, reload again

			continue;
		}

		int tries = 0;
		do {
			print_status(downloader, "Downloading...[%d]\n", job->level);
			resp = http_get(job->iri, NULL, downloader);
		} while (!resp && ++tries < 3);

		if (!resp)
			goto ready;

		mget_cookie_normalize_cookies(job->iri, resp->cookies); // sanitize cookies
		mget_cookie_store_cookies(resp->cookies); // store cookies

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

		if (resp->links) {
			// Found a Metalink answer (RFC 6249 Metalink/HTTP: Mirrors and Hashes).
			// We try to find and download the .meta4 file (RFC 5854).
			// If we can't find the .meta4, download from the link with the highest priority.

			MGET_HTTP_LINK *top_link = NULL, *metalink = NULL;
			int it;

			for (it = 0; it < mget_vector_size(resp->links); it++) {
				MGET_HTTP_LINK *link = mget_vector_get(resp->links, it);
				if (link->rel == link_rel_describedby) {
					if (!strcasecmp(link->type, "application/metalink4+xml") ||
						 !strcasecmp(link->type, "application/metalink+xml"))
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
				add_uri(job, NULL, metalink->uri, 0);
				// dprintf(sockfd, "add uri - %s\n", metalink->uri);
				goto ready;
			} else if (top_link) {
				// no metalink4 description found, create a new job
				add_uri(job, NULL, top_link->uri, 0);
				// dprintf(sockfd, "add uri - %s\n", top_link->uri);
				goto ready;
			}
		}

		if (resp->content_type) {
			if (!strcasecmp(resp->content_type, "application/metalink4+xml")) {
				print_status(downloader, "get metalink4 info\n");
				// save_file(resp, job->local_filename, O_TRUNC);
				metalink4_parse(job, resp);
				if (job->size <= 0) {
					debug_printf("File length %llu - remove job\n", (unsigned long long)job->size);
				} else if (!job->mirrors) {
					debug_printf("File length %llu - remove job\n", (unsigned long long)job->size);
				} else {
					// just loaded a metalink file, create parts and sort mirrors

					// start or resume downloading
					job_validate_file(job);

					if (job->hash_ok) {
						// file already downloaded and checksum ok
					} else {
						// sort mirrors by priority to download from highest priority first
						job_sort_mirrors(job);

						// wake up sleeping workers
						mget_thread_cond_signal(&worker_cond);

						job = NULL; // do not remove this job from queue yet
					}
					goto ready;
				}
			}
			else if (!strcasecmp(resp->content_type, "application/metalink+xml")) {
				print_status(downloader, "get metalink3 info\n");
				// save_file(resp, job->local_filename, O_TRUNC);
				metalink3_parse(job, resp);
				goto ready;
			}
		}

		if (resp->code == 200) {
			if (config.content_disposition && resp->content_filename)
				save_file(resp, resp->content_filename);
			else
				save_file(resp, config.output_document ? config.output_document : job->local_filename);

			if (config.recursive && (!config.level || job->level < config.level + config.page_requisites)) {
				if (resp->content_type) {
					if (!strcasecmp(resp->content_type, "text/html")) {
						html_parse(job, job->level, resp->body->data, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
					} else if (!strcasecmp(resp->content_type, "application/xhtml+xml")) {
						// xml_parse(sockfd, resp, job->iri);
					} else if (!strcasecmp(resp->content_type, "text/css")) {
						css_parse(job, resp->body->data, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
					}
				}
			}
		}
		else if (resp->code == 206 && config.continue_download) { // partial content
			if (config.content_disposition && resp->content_filename)
				append_file(resp, resp->content_filename);
			else
				append_file(resp, config.output_document ? config.output_document : job->local_filename);
		}
		else if (resp->code == 304 && config.timestamping) { // local document is up-to-date
			if (config.recursive && (!config.level || job->level < config.level + config.page_requisites)) {
				const char *ext;

				if (config.content_disposition && resp->content_filename)
					ext = strrchr(resp->content_filename, '.');
				else
					ext = strrchr(job->local_filename, '.');

				if (ext) {
					if (!strcasecmp(ext, ".html") || !strcasecmp(ext, ".htm")) {
						html_parse_localfile(job, job->level, job->local_filename, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
					} else if (!strcasecmp(ext, ".css")) {
						css_parse_localfile(job, job->local_filename, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
					}
				}
			}
		}

		// regular download
ready:
		if (resp) {
			print_status(downloader, "%d %s\n", resp->code, resp->reason);
			http_free_response(&resp);
		}

		// download of single-part file complete, remove from job queue
		// log_printf("- '%s' completed\n",downloader[n].job->uri);
		queue_del(job);
		mget_thread_cond_signal(&main_cond);
	}

	mget_thread_mutex_unlock(&main_mutex);
	http_close(&downloader->conn);

	// if we terminate, tell the other downloaders
	mget_thread_cond_signal(&worker_cond);

	return NULL;
}

struct html_context {
	JOB
		*job;
	MGET_IRI
		*base;
	const char
		*encoding;
	mget_buffer_t
		uri_buf;
	int
		level;
	char
		base_allocated,
		encoding_allocated;
};

static void _html_parse(void *context, int flags, const char *dir, const char *attr, const char *val, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	static int found_content_type;
	struct html_context *ctx = context;

	// Read the encoding from META tag, e.g. from
	//   <meta http-equiv="Content-Type" content="text/html; charset=utf-8">.
	// It overrides the encoding from the HTTP response resp. from the CLI.
	if ((flags & XML_FLG_BEGIN) && tolower(*dir) == 'm' && !strcasecmp(dir, "meta")) {
		found_content_type = 0;
	}

	if ((flags & XML_FLG_ATTRIBUTE) && val) {
		int found = 0;
		char valbuf[len + 1], *value = valbuf;

		memcpy(value, val, len);
		value[len] = 0;

		// info_printf("%02X %s %s '%s' %zd %zd\n", flags, dir, attr, val, len, pos);

		// very simplified
		// see http://stackoverflow.com/questions/2725156/complete-list-of-html-tag-attributes-which-have-a-url-value
		switch (tolower(*attr)) {
		case 'a':
			found = !strcasecmp(attr, "action") || !strcasecmp(attr, "archive");
			break;
		case 'b':
			found = !strcasecmp(attr, "background");
			break;
		case 'c':
			found = !strcasecmp(attr, "code") || !strcasecmp(attr, "codebase") ||
				!strcasecmp(attr, "cite") || !strcasecmp(attr, "classid");
			break;
		case 'd':
			found = !strcasecmp(attr, "data");
			break;
		case 'f':
			found = !strcasecmp(attr, "formaction");
			break;
		case 'h':
			found = !strcasecmp(attr, "href");

			// with --page-requisites: just load inline URLs from the deepest level documents
			if (found && config.recursive && config.page_requisites && config.level && ctx->level >= config.level) {
				// don't load from dir 'A', 'AREA' and 'EMBED'
				if (tolower(*dir) == 'a' && (dir[1] == 0 || !strcasecmp(dir,"area"))) {
					return;
				}
			}

			if (found && tolower(*dir) == 'b' && !strcasecmp(dir,"base")) {
				// found a <BASE href="...">
				// add it to be downloaded, replace old base
				MGET_IRI *iri = mget_iri_parse(value, ctx->encoding);
				if (iri) {
					add_uri(ctx->job, ctx->encoding, value, 0);
					// dprintf(ctx->sockfd, "add uri %s %s\n", ctx->encoding ? ctx->encoding : "-", value);

					if (ctx->base_allocated)
						mget_iri_free(&ctx->base);

					ctx->base = iri;
					ctx->base_allocated = 1;
				}
				return;
			}

			if (!found && !ctx->encoding_allocated) {
				// if we have no encoding yet, read it from META tag, e.g. from
				//   <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
				if (!strcasecmp(dir, "meta")) {
					if (!strcasecmp(attr, "http-equiv") && !strcasecmp(value, "Content-Type"))
						found_content_type = 1;
					else if (found_content_type && !strcasecmp(attr, "content")) {
						http_parse_content_type(value, NULL, &ctx->encoding);
						if (ctx->encoding) {
							ctx->encoding_allocated = 1;
							info_printf(_("URI content encoding = '%s'\n"), ctx->encoding);
						}
					}
				}
			}
			break;
		case 'i':
			found = !strcasecmp(attr, "icon");
			break;
		case 'l':
			found = !strcasecmp(attr, "lowsrc") || !strcasecmp(attr, "longdesc");
			break;
		case 'm':
			found = !strcasecmp(attr, "manifest");
			break;
		case 'p':
			found = !strcasecmp(attr, "profile") || !strcasecmp(attr, "poster");
			break;
		case 's':
			found = !strcasecmp(attr, "src");
			break;
		case 'u':
			found = !strcasecmp(attr, "usemap");
			break;
		}

		if (found) {
			// sometimes the URIs are surrounded by spaces, we ignore them
			while (isspace(*value))
				value++;

			// skip trailing spaces
			for (; len && isspace(value[len - 1]); len--)
				;

			if (len > 1 || (len == 1 && *value != '#')) { // ignore e.g. href='#'
				// log_printf("%02X %s %s=%s\n",flags,dir,attr,val);
				if (mget_iri_relative_to_abs(ctx->base, value, len, &ctx->uri_buf)) {
					// info_printf("%.*s -> %s\n", (int)len, val, ctx->uri_buf.data);
					add_uri(ctx->job, ctx->encoding, ctx->uri_buf.data, 0);
				} else {
					error_printf(_("Cannot resolve relative URI %s\n"), value);
				}
			}
		}
	}
}

// use the xml parser, being prepared that HTML is not XML

void html_parse(JOB *job, int level, const char *data, const char *encoding, MGET_IRI *base)
{
	// create scheme://authority that will be prepended to relative paths
	struct html_context context = { .base = base, .job = job, .level = level, .encoding = encoding };

	mget_buffer_init(&context.uri_buf, (char[1024]){}, 1024);

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	mget_html_parse_buffer(data, _html_parse, &context, HTML_HINT_REMOVE_EMPTY_CONTENT);

	if (context.encoding_allocated)
		xfree(context.encoding);

//		xfree(context.base->connection_part);
	if (context.base_allocated) {
		mget_iri_free(&context.base);
	}

	mget_buffer_deinit(&context.uri_buf);
}

void html_parse_localfile(JOB *job, int level, const char *fname, const char *encoding, MGET_IRI *base)
{
	// create scheme://authority that will be prepended to relative paths
	struct html_context context = { .base = base, .job = job, .level = level, .encoding = encoding };

	mget_buffer_init(&context.uri_buf, (char[1024]){}, 1024);

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	mget_html_parse_file(fname, _html_parse, &context, HTML_HINT_REMOVE_EMPTY_CONTENT);

	if (context.encoding_allocated)
		xfree(context.encoding);

	if (context.base_allocated)
		mget_iri_free(&context.base);

	mget_buffer_deinit(&context.uri_buf);
}

struct css_context {
	JOB
		*job;
	MGET_IRI
		*base;
	const char
		*encoding;
	mget_buffer_t
		uri_buf;
	int
		sockfd;
	char
		encoding_allocated;
};

static void _css_parse_encoding(void *context, const char *encoding, size_t len)
{
	struct css_context *ctx = context;

	// take only the first @charset rule
	if (!ctx->encoding_allocated && mget_strncasecmp(ctx->encoding, encoding, len)) {
		ctx->encoding = strndup(encoding, len);
		ctx->encoding_allocated = 1;
		info_printf(_("URI content encoding = '%s'\n"), ctx->encoding);
	}
}

static void _css_parse_uri(void *context, const char *url, size_t len, size_t pos G_GNUC_MGET_UNUSED)
{
	struct css_context *ctx = context;

	if (len > 1 || (len == 1 && *url != '#')) {
		// ignore e.g. href='#'
		if (mget_iri_relative_to_abs(ctx->base, url, len, &ctx->uri_buf)) {
			add_uri(ctx->job, ctx->encoding, ctx->uri_buf.data, 0);
		} else {
			error_printf(_("Cannot resolve relative URI %.*s\n"), (int)len, url);
		}
	}
}

void css_parse(JOB *job, const char *data, const char *encoding, MGET_IRI *base)
{
	// create scheme://authority that will be prepended to relative paths
	struct css_context context = { .base = base, .job = job, .encoding = encoding };

	mget_buffer_init(&context.uri_buf, (char[1024]){}, 1024);

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	mget_css_parse_buffer(data, _css_parse_uri, _css_parse_encoding, &context);

	if (context.encoding_allocated)
		xfree(context.encoding);

	mget_buffer_deinit(&context.uri_buf);
}

void css_parse_localfile(JOB *job, const char *fname, const char *encoding, MGET_IRI *base)
{
	// create scheme://authority that will be prepended to relative paths
	struct css_context context = { .base = base, .job = job, .encoding = encoding };

	mget_buffer_init(&context.uri_buf, (char[1024]){}, 1024);

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	mget_css_parse_file(fname, _css_parse_uri, _css_parse_encoding, &context);

	if (context.encoding_allocated)
		xfree(context.encoding);

	mget_buffer_deinit(&context.uri_buf);
}

static long long G_GNUC_MGET_NONNULL_ALL get_file_size(const char *fname)
{
	struct stat st;
	
	if (stat(fname, &st)==0) {
		return st.st_size;
	}

	return 0;
}

static time_t G_GNUC_MGET_NONNULL_ALL get_file_mtime(const char *fname)
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

#ifdef CLOCK_REALTIME
	clock_gettime(CLOCK_REALTIME, &timespecs[0]);
#else
	timespecs[0].tv_sec = time(NULL);
	timespecs[0].tv_nsec = 0;
#endif
	timespecs[1].tv_sec = modified;
	timespecs[1].tv_nsec = 0;

	if (futimens(fd, timespecs) == -1)
		error_printf (_("Failed to set file date: %s\n"), strerror (errno));
}

static void G_GNUC_MGET_NONNULL((1)) _save_file(MGET_HTTP_RESPONSE *resp, const char *fname, int flag)
{
	char *alloced_fname = NULL;
	int fd, multiple, fnum;
	size_t fname_length = 0;

	if (config.spider || !fname)
		return;

	// - optimistic approach expects data being written without error
	// - to be Wget compatible: quota_modify_read() returns old quota value
	if (config.quota && quota_modify_read(config.save_headers ? resp->header->length + resp->body->length : resp->body->length) >= config.quota)
		return;

	if (fname == config.output_document) {
		// <fname> can only be NULL if config.delete_after is set
		if (!strcmp(fname, "-")) {
			size_t rc;

			if (config.save_headers) {
				if ((rc = fwrite(resp->header->data, 1, resp->header->length, stdout)) != resp->header->length)
					error_printf(_("Failed to write to STDOUT (%zu, errno=%d)\n"), rc, errno);
			}

			if ((rc = fwrite(resp->body->data, 1, resp->body->length, stdout)) != resp->body->length)
				error_printf(_("Failed to write to STDOUT (%zu, errno=%d)\n"), rc, errno);

			return;
		}

		if (config.delete_after)
			return;

		flag = O_APPEND;
	}

	if (config.adjust_extension && resp && resp->content_type) {
		const char *ext;

		if (!strcasecmp(resp->content_type, "text/html")) {
			ext = ".html";
		} else if (!strcasecmp(resp->content_type, "text/css")) {
			ext = ".css";
		} else
			ext = NULL;

		if (ext) {
			size_t ext_length = strlen(ext);

			if ((fname_length = strlen(fname)) >= ext_length && strcasecmp(fname + fname_length - ext_length, ext)) {
				alloced_fname = xmalloc(fname_length + ext_length + 1);
				strcpy(alloced_fname, fname);
				strcpy(alloced_fname + fname_length, ext);
				fname = alloced_fname;
			}
		}
	}

	if (flag == O_APPEND || !config.clobber || config.timestamping || (config.recursive && config.directories)) {
		multiple = 0;
		if (flag == O_TRUNC && !(config.recursive && config.directories))
			flag = O_EXCL;
	} else {
		// wget compatibility: "clobber" means generating of .x files
		multiple = 1;
		if (fname_length)
			fname_length += 16;
		else
			fname_length = strlen(fname) + 16;
		if (flag == O_TRUNC)
			flag = O_EXCL;
	}

	fd = open(fname, O_WRONLY | flag | O_CREAT, 0644);

	for (fnum = 0; fnum < 999;) { // just prevent endless loop
		char unique[fname_length + 1];

		if (fd != -1) {
			ssize_t rc;

			if (config.save_headers) {
				if ((rc = write(fd, resp->header->data, resp->header->length)) != (ssize_t)resp->header->length)
					error_printf(_("Failed to write file %s (%zd, errno=%d)\n"), fnum ? unique : fname, rc, errno);
			}

			if ((rc = write(fd, resp->body->data, resp->body->length)) != (ssize_t)resp->body->length)
				error_printf(_("Failed to write file %s (%zd, errno=%d)\n"), fnum ? unique : fname, rc, errno);

			if ((flag & (O_TRUNC | O_EXCL)) && resp->last_modified)
				set_file_mtime(fd, resp->last_modified);

			if (flag == O_APPEND)
				info_printf("appended to '%s'\n", fnum ? unique : fname);
			else
				info_printf("saved '%s'\n", fnum ? unique : fname);

			close(fd);
		}
		else if (multiple && (fd == -1 && errno == EEXIST)) {
			snprintf(unique, sizeof(unique), "%s.%d", fname, ++fnum);
			fd = open(unique, O_WRONLY | flag | O_CREAT, 0644);
			continue;
		}

		break;
	}

	if (fd == -1) {
		if (errno == EEXIST && fnum < 999)
			error_printf(_("File '%s' already there; not retrieving.\n"), fname);
		else
			error_printf(_("Failed to open '%s' (errno=%d)\n"), fname, errno);
	}

	xfree(alloced_fname);
}

static void G_GNUC_MGET_NONNULL((1)) save_file(MGET_HTTP_RESPONSE *resp, const char *fname)
{
	_save_file(resp, fname, O_TRUNC);
}

static void G_GNUC_MGET_NONNULL((1)) append_file(MGET_HTTP_RESPONSE *resp, const char *fname)
{
	_save_file(resp, fname, O_APPEND);
}

//void download_part(int sockfd, JOB *job, PART *part)

void download_part(DOWNLOADER *downloader)
{
	JOB *job = downloader->job;
	PART *part = downloader->part;
	int mirror_index = downloader->id % mget_vector_size(job->mirrors);

	do {
		MGET_HTTP_RESPONSE *msg;
		MIRROR *mirror = mget_vector_get(job->mirrors, mirror_index);

		print_status(downloader, "downloading part %d/%d (%zd-%zd) %s from %s (mirror %d)\n",
			part->id, mget_vector_size(job->parts),
			part->position, part->position + part->length - 1, job->name, mirror->iri->host, mirror_index);

		mirror_index = (mirror_index + 1) % mget_vector_size(job->mirrors);

		msg = http_get(mirror->iri, part, downloader);
		if (msg) {
			mget_cookie_store_cookies(msg->cookies); // sanitize and store cookies

			if (msg->code != 200 && msg->code != 206) {
				print_status(downloader, "part %d download error %d\n", part->id, msg->code);
			} else if (!msg->body) {
				print_status(downloader, "part %d download error 'empty body'\n", part->id);
			} else if (msg->body->length != (size_t)part->length) {
				print_status(downloader, "part %d download error '%zd bytes of %zd expected'\n",
					part->id, msg->body->length, part->length);
			} else {
				int fd;

				print_status(downloader, "part %d downloaded\n", part->id);
				if ((fd = open(job->name, O_WRONLY | O_CREAT, 0644)) != -1) {
					if (lseek(fd, part->position, SEEK_SET) != -1) {
						ssize_t nbytes;

						if ((nbytes = write(fd, msg->body->data, msg->body->length)) == (ssize_t)msg->body->length)
							part->done = 1; // set this when downloaded ok
						else
							error_printf(_("Failed to write %zd bytes (%zd)\n"), msg->body->length, nbytes);
					} else
						error_printf(_("Failed to lseek to %llu\n"), (unsigned long long)part->position);
					close(fd);
				} else
					error_printf(_("Failed to write open %s\n"), job->name);

			}

			http_free_response(&msg);
		}
	} while (!part->done);
}

MGET_HTTP_RESPONSE *http_get(MGET_IRI *iri, PART *part, DOWNLOADER *downloader)
{
	MGET_IRI *dont_free = iri;
	MGET_HTTP_CONNECTION *conn;
	MGET_HTTP_RESPONSE *resp = NULL;
	MGET_VECTOR *challenges = NULL;
//	int max_redirect = 3;

	while (iri) {
		if (downloader->conn && !mget_strcmp(downloader->conn->esc_host, iri->host) &&
			downloader->conn->scheme == iri->scheme &&
			!mget_strcmp(downloader->conn->port, iri->resolv_port))
		{
			debug_printf("reuse connection %s\n", downloader->conn->esc_host);
		} else {
			if (downloader->conn) {
				debug_printf("close connection %s\n", downloader->conn->esc_host);
				http_close(&downloader->conn);
			}
			downloader->conn = http_open(iri);
			if (downloader->conn) {
				debug_printf("opened connection %s\n", downloader->conn->esc_host);
			}
		}
		conn = downloader->conn;

		if (conn) {
			MGET_HTTP_REQUEST *req;

			req = http_create_request(iri, "GET");

			if (config.continue_download || config.timestamping) {
				const char *local_filename = downloader->job->local_filename;

				if (config.continue_download)
					http_add_header_printf(req, "Range: bytes=%llu-",
						get_file_size(local_filename));

				if (config.timestamping) {
					time_t mtime = get_file_mtime(local_filename);

					if (mtime) {
						char http_date[32];

						http_print_date(mtime + 1, http_date, sizeof(http_date));
						http_add_header(req, "If-Modified-Since", http_date);
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
#ifdef WITH_ZLIB
			http_add_header_line(req,
				/*				"Accept-Encoding: gzip\r\n"\
				"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.5) Gecko/20100101 Firefox/10.0.5 Iceweasel/10.0.5\r\n"\
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8\r\n"
				"Accept-Language: en-us,en;q=0.5\r\n");
				 */
				"Accept-Encoding: gzip, deflate\r\n"
				);
#endif

			http_add_header_line(req, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");

//			if (config.spider && !config.recursive)
//				http_add_header_if_modified_since(time(NULL));
//				http_add_header_line(req, "If-Modified-Since: Wed, 29 Aug 2012 00:00:00 GMT\r\n");

			if (config.user_agent)
				http_add_header(req, "User-Agent", config.user_agent);

			if (config.keep_alive)
				http_add_header_line(req, "Connection: keep-alive\r\n");

			if (!config.cache)
				http_add_header_line(req, "Pragma: no-cache\r\n");

			if (config.referer)
				http_add_header(req, "Referer", config.referer);
			else if (downloader->job->referer) {
				MGET_IRI *referer = downloader->job->referer;
				mget_buffer_t buf;

				mget_buffer_init(&buf, (char[256]){}, 256);

				mget_buffer_strcat(&buf, referer->scheme);
				mget_buffer_memcat(&buf, "://", 3);
				mget_buffer_strcat(&buf, referer->host);
				mget_buffer_memcat(&buf, "/", 1);
				mget_iri_get_escaped_resource(referer, &buf);

				http_add_header(req, "Referer", buf.data);
				mget_buffer_deinit(&buf);
			}

			if (challenges) {
				// There might be more than one challenge, we could select the securest one.
				// Prefer 'Digest' over 'Basic'
				// the following adds an Authorization: HTTP header
				MGET_HTTP_CHALLENGE *challenge, *selected_challenge = NULL;

				for (int it = 0; it < mget_vector_size(challenges); it++) {
					challenge = mget_vector_get(challenges, it);

					if (strcasecmp(challenge->auth_scheme, "digest")) {
						selected_challenge = challenge;
						break;
					}
					else if (strcasecmp(challenge->auth_scheme, "basic")) {
						if (!selected_challenge)
							selected_challenge = challenge;
					}
				}

				if (selected_challenge)
					http_add_credentials(req, selected_challenge, config.http_username, config.http_password);
			}

			if (part)
				http_add_header_printf(req, "Range: bytes=%llu-%llu",
					(unsigned long long) part->position, (unsigned long long) part->position + part->length - 1);

			// add cookies
			if (config.cookies) {
				const char *cookie_string;

				if ((cookie_string = mget_cookie_create_request_header(iri))) {
					http_add_header(req, "Cookie", cookie_string);
					xfree(cookie_string);
				}
			}

			if (http_send_request(conn, req) == 0) {
				resp = http_get_response(conn, NULL, req, config.save_headers || config.server_response ? MGET_HTTP_RESPONSE_KEEPHEADER : 0);
			}

			http_free_request(&req);
		} else break;

		if (!resp) {
			http_close(&downloader->conn);
			break;
		}

		if (config.server_response)
			info_printf("# got header %zd bytes:\n%s\n\n", resp->header->length, resp->header->data);

		// server doesn't support keep-alive or want us to close the connection
		if (!resp->keep_alive)
			http_close(&downloader->conn);

		if (resp->code == 302 && resp->links && resp->digests)
			break; // 302 with Metalink information

		if (resp->code == 401 && !challenges) { // Unauthorized
			http_free_challenges(&challenges);
			if ((challenges = resp->challenges)) {
				resp->challenges = NULL;
				http_free_response(&resp);
				continue; // try again with credentials
			}
			break;
		}

		// 304 Not Modified
		if (resp->code / 100 == 2 || resp->code / 100 >= 4 || resp->code == 304)
			break; // final response

		if (resp->location) {
			mget_buffer_t uri_buf;

			mget_cookie_normalize_cookies(iri, resp->cookies);
			mget_cookie_store_cookies(resp->cookies);

			mget_buffer_init(&uri_buf, (char[1024]){}, 1024);

			mget_iri_relative_to_abs(iri, resp->location, strlen(resp->location), &uri_buf);

			if (!part) {
				add_uri(downloader->job, NULL, uri_buf.data, 1);
//				dprintf(downloader->sockfd[1], "redirect - %s\n", uri_buf.data);
				mget_buffer_deinit(&uri_buf);
				break;
			} else {
				// directly follow when using metalink
				if (iri != dont_free)
					mget_iri_free(&iri);
				iri = mget_iri_parse(uri_buf.data, NULL);
				mget_buffer_deinit(&uri_buf);
			}
		}

		http_free_response(&resp);
	}

	if (iri != dont_free)
		mget_iri_free(&iri);

	http_free_challenges(&challenges);

	return resp;
}

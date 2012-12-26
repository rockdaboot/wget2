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

#include <pthread.h>
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

#include "xalloc.h"
#include "iri.h"
#include "net.h"
#include "utils.h"
#include "list.h"
#include "vector.h"
#include "http.h"
#include "log.h"
#include "job.h"
#include "printf.h"
#include "xml.h"
#include "css.h"
#include "options.h"
#include "metalink.h"
#include "blacklist.h"
#include "ssl.h"

typedef struct {
	pthread_t
		tid;
	JOB
		*job;
	PART
		*part;
	HTTP_CONNECTION
		*conn;
	char
		*buf;
	size_t
		bufsize;
	int
		sockfd[2],
		id;
} DOWNLOADER;

//static HTTP_RESPONSE
//	*http_get_uri(const char *uri);
static void
	download_part(DOWNLOADER *downloader),
	save_file(HTTP_RESPONSE *resp, const char *fname),
	append_file(HTTP_RESPONSE *resp, const char *fname),
	html_parse(int sockfd, const char *data, const char *encoding, IRI *iri),
	html_parse_localfile(int sockfd, const char *fname, const char *encoding, IRI *iri),
	css_parse(int sockfd, const char *data, const char *encoding, IRI *iri),
	css_parse_localfile(int sockfd, const char *fname, const char *encoding, IRI *iri);
HTTP_RESPONSE
	*http_get(IRI *iri, PART *part, DOWNLOADER *downloader);

static DOWNLOADER
	*downloader;
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

static const char * NONNULL_ALL get_local_filename(IRI *iri)
{
	buffer_t buf;
	const char *fname;
	int directories;

	if (config.spider || config.output_document)
		return NULL;

	directories = !!config.recursive;

	if (config.directories == 0)
		directories = 0;

	if (config.force_directories == 1)
		directories = 1;

	buffer_init(&buf, NULL, 256);

	if (config.directory_prefix && *config.directory_prefix) {
		buffer_strcat(&buf, config.directory_prefix);
		buffer_memcat(&buf, "/", 1);
	}

	if (directories) {
		if (config.protocol_directories && iri->scheme && *iri->scheme) {
			buffer_strcat(&buf, iri->scheme);
			buffer_memcat(&buf, "/", 1);
		}
		if (config.host_directories && iri->host && *iri->host) {
			iri_get_escaped_host(iri, &buf);
			// buffer_memcat(&buf, "/", 1);
		}

		if (config.cut_directories) {
			// cut directories
			buffer_t path_buf;
			const char *p;
			int n;

			buffer_init(&path_buf, NULL, 256);
			iri_get_escaped_path(iri, &path_buf);

			for (n = 0, p = path_buf.data; n < config.cut_directories && p; n++) {
				p = strchr(*p =='/' ? p + 1 : p, '/');
			}
			if (!p) {
				// we can't strip this many path elements, just use the filename
				p = strrchr(path_buf.data, '/');
				if (!p) {
					p = path_buf.data;
					if (*p != '/')
						buffer_memcat(&buf, "/", 1);
					buffer_strcat(&buf, p);
				}
			}

			buffer_deinit(&path_buf);
		} else {
			iri_get_escaped_path(iri, &buf);
		}

		fname = iri_get_escaped_query(iri, &buf);
	} else {
		fname = iri_get_escaped_file(iri, &buf);
	}

	// create the complete path
	if (*fname) {
		const char *p1, *p2;

		for (p1 = fname; *p1 && (p2 = strchr(p1, '/')); p1 = p2 + 1) {
			*(char *)p2 = 0; // replace path separator

			// relative paths should have been normalized earlier,
			// but for security reasons, don't trust myself...
			if (*p1 == '.' && p1[1] == '.')
				err_printf_exit(_("Internal error: Unexpected relative path: '%s'\n"), fname);

			if (mkdir(fname, 0755) != 0 && errno != EEXIST) {
				err_printf(_("Failed to make directory '%s'\n"), fname);
				*(char *)p2 = '/'; // restore path separator
				return fname;
			} else log_printf("mkdir %s\n", fname);

			*(char *)p2 = '/'; // restore path separator
		}
	}

	if (config.delete_after) {
		buffer_deinit(&buf);
		fname = NULL;
	} else
		log_printf("local filename = '%s'\n", fname);

	return fname;
}

static int schedule_download(JOB *job, PART *part)
{
	if (config.quota && quota >= config.quota)
		return 0;

	if (job) {
		static int offset;
		int n;

		for (n = 0; n < config.num_threads; n++) {
			if (downloader[offset].job == NULL) {
				downloader[offset].job = job;
				downloader[offset].part = part;
				if (part)
					part->inuse = 1;
				else
					job->inuse = 1;

				dprintf(downloader[offset].sockfd[0], "go\n");
				return 1;
			}

			if (++offset >= config.num_threads)
				offset = 0;
		}
	}

	return 0;
}

// Since quota may change at any time in a threaded environment,
// we have to modify and check the quota in one (protected) step.
static long long quota_modify_read(size_t nbytes)
{
	static pthread_mutex_t
		mutex = PTHREAD_MUTEX_INITIALIZER;
	size_t old_quota;

	pthread_mutex_lock(&mutex);
	old_quota = quota;
	quota += nbytes;
	pthread_mutex_unlock(&mutex);

	return old_quota;
}

static JOB *add_url_to_queue(const char *url, IRI *base, const char *encoding)
{
	IRI *iri;
	JOB *job;

	if (base) {
		char sbuf[256];
		buffer_t buf;

		buffer_init(&buf, sbuf, sizeof(sbuf));
		iri = iri_parse(iri_relative_to_absolute(base, url, strlen(url), &buf), encoding);
		buffer_deinit(&buf);
	} else {
		// no base and no buf: just check URL for being an absolute URI
		iri = iri_parse(iri_relative_to_absolute(NULL, url, strlen(url), NULL), encoding);
	}

	if (!iri) {
		err_printf(_("Cannot resolve relative URI %s\n"), url);
		return NULL;
	}

	job = queue_add(blacklist_add(iri));

	if (job) {
		if (!config.output_document)
			job->local_filename = get_local_filename(job->iri);

		if (config.recursive && !config.span_hosts) {
			// only download content from hosts given on the command line or from input file
			if (!stringmap_get(config.exclude_domains, job->iri->host))
				stringmap_put_ident(config.domains, job->iri->host);
		}
	}

	return job;
}

static void nop(int sig)
{
	if (sig == SIGTERM) {
		terminate = 1; // set global termination flag
	} else if (sig == SIGINT) {
		abort();
	}
}

int main(int argc, const char *const *argv)
{
	int n, rc, maxfd, nfds, inputfd = -1;
	size_t bufsize = 0;
	char *buf = NULL;
	pthread_attr_t attr;
	fd_set rset;
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

	//	tcp_settracefunction(NULL,(void (*)(const char *, ...))log_printf);
	//	tcp_seterrorfunction(NULL,(void (*)(const char *, ...))err_printf);
	//	tcp_config(NULL,C_TRACE,1);

	n = init(argc, argv);

	for (; n < argc; n++) {
		add_url_to_queue(argv[n], config.base, config.local_encoding);
	}

	if (config.input_file) {
		if (config.force_html) {
			// read URLs from HTML file
			html_parse_localfile(-1, config.input_file, config.remote_encoding, config.base);
		}
		else if (config.force_css) {
			// read URLs from CSS file
			css_parse_localfile(-1, config.input_file, config.remote_encoding, config.base);
		}
		else if (strcmp(config.input_file, "-")) {
			int fd;
			ssize_t len;

			// read URLs from input file
			if ((fd = open(config.input_file, O_RDONLY))) {
				while ((len = fdgetline0(&buf, &bufsize, fd)) > 0) {
					add_url_to_queue(buf, config.base, config.local_encoding);
				}
				close(fd);
			} else
				err_printf(_("Failed to open input file %s\n"), config.input_file);
		} else {
			if (isatty(STDIN_FILENO)) {
				ssize_t len;

				// read URLs from STDIN
				while ((len = fdgetline0(&buf, &bufsize, STDIN_FILENO)) >= 0) {
					add_url_to_queue(buf, config.base, config.local_encoding);
				}
			} else
				inputfd = STDIN_FILENO;
		} // else read later asynchronous and process each URL immediately
	}

	downloader = xcalloc(config.num_threads, sizeof(DOWNLOADER));

	for (n = 0; n < config.num_threads; n++) {
		downloader[n].id = n;

		// create two-way communication path
		socketpair(AF_UNIX, SOCK_STREAM, 0, downloader[n].sockfd);

		// reading & writing to pipe must not block
		fcntl(downloader[n].sockfd[0], F_SETFL, O_NDELAY);
		fcntl(downloader[n].sockfd[1], F_SETFL, O_NDELAY);

		// init thread attributes
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
		// pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
		pthread_attr_setschedpolicy(&attr, SCHED_OTHER);

		if ((rc = pthread_create(&downloader[n].tid, &attr, downloader_thread, &downloader[n])) != 0) {
			err_printf(_("Failed to start downloader, error %d\n"), rc);
			close(downloader[n].sockfd[0]);
			close(downloader[n].sockfd[1]);
		}

		pthread_attr_destroy(&attr);

		if (queue_get(&downloader[n].job, NULL)) {
			dprintf(downloader[n].sockfd[0], "go\n");
		}
	}

	while (!queue_empty() || inputfd != -1) {
		if (config.quota && quota >= config.quota) {
			info_printf(_("Quota of %llu bytes reached - stopping.\n"), config.quota);
			break;
		}

		FD_ZERO(&rset);
		for (maxfd = n = 0; n < config.num_threads; n++) {
			FD_SET(downloader[n].sockfd[0], &rset);
			if (downloader[n].sockfd[0] > maxfd)
				maxfd = downloader[n].sockfd[0];
		}
		if (inputfd != -1) {
			FD_SET(inputfd, &rset);
			if (inputfd > maxfd)
				maxfd = inputfd;
		}

		// later, set timeout here
		if ((nfds = select(maxfd + 1, &rset, NULL, NULL, NULL)) <= 0) {
			// timeout or error
			if (nfds == -1) {
				if (errno == EINTR) break;
				err_printf(_("Failed to select, error %d\n"), errno);
			}
			continue;
		}

		if (inputfd != -1 && FD_ISSET(inputfd, &rset)) {
			ssize_t len;

			while ((len = fdgetline0(&buf, &bufsize, inputfd)) > 0) {
				JOB *job = add_url_to_queue(buf, config.base, config.local_encoding);
				schedule_download(job, NULL);
			}

			// input closed, don't read from it any more
			if (len == -1)
				inputfd = -1;

			nfds--;
		}

		for (n = 0; n < config.num_threads && nfds > 0 && !terminate; n++) {
			if (FD_ISSET(downloader[n].sockfd[0], &rset)) {
				while (!terminate && fdgetline0(&downloader[n].buf, &downloader[n].bufsize, downloader[n].sockfd[0]) > 0) {
					JOB *job = downloader[n].job;
					PART *part = downloader[n].part;
					char *buf = downloader[n].buf;
					int pos;

					log_printf("- [%d] %s\n", n, buf);

					if (!strncmp(buf, "sts ", 4)) {
						if (job && job->iri->uri)
							info_printf("status '%s' for %s\n", buf + 4, job->iri->uri);
						else
							info_printf("status '%s'\n", buf + 4);
					} else if (!strcmp(buf, "ready")) {
						if (job) {
							downloader[n].part = NULL;
							// log_printf("got job %p %d\n",job->pieces,job->hash_ok);
							if (!job->pieces || job->hash_ok) {
								// download of single-part file complete, remove from job queue
								// log_printf("- '%s' completed\n",downloader[n].job->uri);
								queue_del(job);
							} else if (part) {
								if (part->done) {
									// check if all parts are done (downloaded + hash-checked)
									int all_done = 1, it;
									for (it = 0; it < vec_size(job->parts); it++) {
										PART *part = vec_get(job->parts, it);
										if (!part->done) {
											all_done = 0;
											break;
										}
									}
									// log_printf("all_done=%d\n",all_done);
									if (all_done && vec_size(job->hashes) > 0) {
										// check integrity of complete file
										dprintf(downloader[n].sockfd[0], "check\n");
										continue;
									}
								} else part->inuse = 0; // something was wrong, reload again
							} else if (job->size <= 0) {
								log_printf("File length %llu - remove job\n", (unsigned long long)job->size);
								queue_del(job);
							} else if (!job->mirrors) {
								log_printf("File length %llu - remove job\n", (unsigned long long)job->size);
								queue_del(job);
							} else {
								// log_printf("just loaded metalink file\n");
								// just loaded a metalink file, create parts and sort mirrors
								// job_create_parts(job);

								// start or resume downloading
								job_validate_file(job);

								if (job->hash_ok) {
									// file ok or download of non-chunked file complete, remove from job queue
									// log_printf("- '%s' completed\n",downloader[n].job->uri);
									queue_del(job);
								} else {
									int it;

									// sort mirrors by priority to download from highest priority first
									job_sort_mirrors(job);

									for (it = 0; it < vec_size(job->parts); it++)
										if (schedule_download(job, vec_get(job->parts, it)) == 0)
											break; // now all downloaders have a job
								}
							}
						}

						if (!config.quota || (config.quota && config.quota > quota)) {
							if (queue_get(&downloader[n].job, &downloader[n].part))
								dprintf(downloader[n].sockfd[0], "go\n");
						}
					} else if (!strncmp(buf, "chunk ", 6)) {
						if (!strncasecmp(buf + 6, "mirror ", 7)) {
							MIRROR mirror;

							if (!job->mirrors)
								job->mirrors = vec_create(4, 4, NULL);

							memset(&mirror, 0, sizeof(MIRROR));
							pos = 0;
							if (sscanf(buf + 13, "%2s %6d %n", mirror.location, &mirror.priority, &pos) >= 2 && pos) {
								mirror.iri = iri_parse(buf + 13 + pos, NULL);
								vec_add(job->mirrors, &mirror, sizeof(MIRROR));
							} else
								err_printf(_("Failed to parse metalink mirror '%s'\n"), buf);
						} else if (!strncasecmp(buf + 6, "hash ", 5)) {
							// hashes for the complete file
							HASH hash;

							if (!job->hashes)
								job->hashes = vec_create(4, 4, NULL);

							memset(&hash, 0, sizeof(HASH));
							if (sscanf(buf + 11, "%15s %127s", hash.type, hash.hash_hex) == 2) {
								vec_add(job->hashes, &hash, sizeof(HASH));
							} else
								err_printf(_("Failed to parse metalink hash '%s'\n"), buf);
						} else if (!strncasecmp(buf + 6, "piece ", 6)) {
							// hash for a piece of the file
							PIECE piece, *piecep;

							if (!job->pieces)
								job->pieces = vec_create(32, 32, NULL);

							memset(&piece, 0, sizeof(PIECE));
							if (sscanf(buf + 12, "%15llu %15s %127s", (unsigned long long *)&piece.length, piece.hash.type, piece.hash.hash_hex) == 3) {
								piecep = vec_get(job->pieces, vec_size(job->pieces) - 1);
								if (piecep)
									piece.position = piecep->position + piecep->length;
								vec_add(job->pieces, &piece, sizeof(PIECE));
							} else
								err_printf(_("Failed to parse metalink piece '%s'\n"), buf);
						} else if (!strncasecmp(buf + 6, "name ", 5)) {
							job->name = strdup(buf + 11);
						} else if (!strncasecmp(buf + 6, "size ", 5)) {
							job->size = atoll(buf + 11);
						}
					} else if (!strncmp(buf, "add uri ", 8) || !strncmp(buf, "redirect ", 9)) {
						JOB *new_job;
						IRI *iri;
						char *p, *encoding;

						if (*buf == 'r') {
							if (job->redirection_level >= config.max_redirect) {
								continue;
							}
							encoding = buf + 9;
						} else
							encoding = buf + 8;

						for (p = encoding; *p != ' '; p++);
						*p = 0;

						if (*encoding == '-')
							encoding = NULL;
						
						iri = iri_parse(p + 1, encoding);

						if (config.recursive && !config.span_hosts) {
							// only download content from given hosts
							if (!iri->host || !stringmap_get(config.domains, iri->host) || stringmap_get(config.exclude_domains, iri->host)) {
								info_printf("URI '%s' not followed\n", iri->uri);
								iri_free(&iri);
							}
						}

						if ((new_job = queue_add(blacklist_add(iri)))) {
							if (!config.output_document)
								new_job->local_filename = get_local_filename(new_job->iri);
							if (*buf == 'r') {
								new_job->redirection_level = job->redirection_level + 1;
								new_job->referer = job->referer;
							} else {
								new_job->referer = job->iri;
							}
							schedule_download(new_job, NULL);
						}
					}
				}
				nfds--;
			}
		}
	}

	xfree(buf);

	// stop downloaders
	for (n = 0; n < config.num_threads; n++) {
		close(downloader[n].sockfd[0]);
		close(downloader[n].sockfd[1]);
		http_close(&downloader[n].conn);
		xfree(downloader[n].buf);
		if (pthread_kill(downloader[n].tid, SIGTERM) == -1)
			err_printf(_("Failed to kill downloader #%d\n"), n);
	}

	for (n = 0; n < config.num_threads; n++) {
		//		struct timespec ts;
		//		clock_gettime(CLOCK_REALTIME, &ts);
		//		ts.tv_sec += 1;
		// if the thread is not detached, we have to call pthread_join()/pthread_timedjoin_np()
		// else we will have a huge memory leak
		int rc;
		//		if ((rc=pthread_timedjoin_np(downloader[n].tid, NULL, &ts))!=0)
		if ((rc = pthread_join(downloader[n].tid, NULL)) != 0)
			err_printf(_("Failed to wait for downloader #%d (%d %d)\n"), n, rc, errno);
	}

	if (config.save_cookies)
		cookie_save(config.save_cookies, config.keep_session_cookies);

	if (config.delete_after && config.output_document)
		unlink(config.output_document);

	if (config.debug)
		blacklist_print();

	// freeing to avoid disguising valgrind output
	cookie_free_public_suffixes();
	cookie_free_cookies();
	ssl_deinit();
	queue_free();
	blacklist_free();
	xfree(downloader);
	deinit();

	return EXIT_SUCCESS;
}

void *downloader_thread(void *p)
{
	DOWNLOADER *downloader = p;
	JOB *job;
	char *buf = NULL;
	size_t bufsize = 0;
	fd_set rset;
	int nfds;
	//	unsigned int seed=(unsigned int)(time(NULL)|pthread_self());
	int sockfd = downloader->sockfd[1];

	downloader->tid = pthread_self(); // to avoid race condition

	while (!terminate) {
		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);

		// later, set timeout here
		if ((nfds = select(sockfd + 1, &rset, NULL, NULL, NULL)) <= 0) {
			// timeout or error
			if (nfds == -1) {
				if (errno == EINTR || errno == EBADF) break;
				err_printf(_("Failed to select, error %d\n"), errno);
			}
			continue;
		}

		while (!terminate && fdgetline0(&buf, &bufsize, sockfd) > 0) {
			log_printf("+ [%d] %s\n", downloader->id, buf);
			job = downloader->job;
			if (!strcmp(buf, "check")) {
				dprintf(sockfd, "sts %s checking...\n", job->name);
				job_validate_file(job);
				if (job->hash_ok)
					log_printf("sts check ok");
				else
					log_printf("sts check failed");
				dprintf(sockfd, "ready\n");
			} else if (!strcmp(buf, "go")) {
				HTTP_RESPONSE *resp = NULL;

				if (!downloader->part) {
					int tries = 0;

					do {
						dprintf(sockfd, "sts Downloading...\n");
						resp = http_get(job->iri, NULL, downloader);
					} while (!resp && ++tries < 3);

					if (!resp)
						goto ready;

					cookie_normalize_cookies(job->iri, resp->cookies); // sanitize cookies
					cookie_store_cookies(resp->cookies); // store cookies

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

						HTTP_LINK *top_link = NULL, *metalink = NULL;
						int it;

						for (it = 0; it < vec_size(resp->links); it++) {
							HTTP_LINK *link = vec_get(resp->links, it);
							if (link->rel == link_rel_describedby) {
								if (!strcasecmp(link->type, "application/metalink4+xml")) {
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
							// found a link to a metalink4 description, create a new job
							dprintf(sockfd, "add uri - %s\n", metalink->uri);
							goto ready;
						} else if (top_link) {
							// no metalink4 description found, create a new job
							dprintf(sockfd, "add uri - %s\n", top_link->uri);
							goto ready;
						}
					}

					if (resp->content_type) {
						if (!strcasecmp(resp->content_type, "application/metalink4+xml")) {
							dprintf(sockfd, "sts get metalink info\n");
							// save_file(resp, job->local_filename, O_TRUNC);
							metalink4_parse(sockfd, resp);
							goto ready;
						}
					}

					if (resp->code == 200) {
						save_file(resp, config.output_document ? config.output_document : job->local_filename);

						if (config.recursive) {
							if (resp->content_type) {
								if (!strcasecmp(resp->content_type, "text/html")) {
									html_parse(sockfd, resp->body->data, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
								} else if (!strcasecmp(resp->content_type, "application/xhtml+xml")) {
									// xml_parse(sockfd, resp, job->iri);
								} else if (!strcasecmp(resp->content_type, "text/css")) {
									css_parse(sockfd, resp->body->data, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
								}
							}
						}
					}
					else if (resp->code == 206 && config.continue_download) { // partial content
						append_file(resp, config.output_document ? config.output_document : job->local_filename);
					}
					else if (resp->code == 304 && config.timestamping) { // local document is up-to-date
						if (config.recursive) {
							const char *ext = strrchr(job->local_filename, '.');

							if (ext) {
								if (!strcasecmp(ext, ".html") || !strcasecmp(ext, ".htm")) {
									html_parse_localfile(sockfd, job->local_filename, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
								} else if (!strcasecmp(ext, ".css")) {
									css_parse_localfile(sockfd, job->local_filename, resp->content_type_encoding ? resp->content_type_encoding : config.remote_encoding, job->iri);
								}
							}
						}
					}

				} else {
					// download metalink part
					download_part(downloader);
				}

				// regular download
ready:
				if (resp) {
					dprintf(sockfd, "sts %d %s\n", resp->code, resp->reason);
					http_free_response(&resp);
				}
				dprintf(sockfd, "ready\n");
			}
		}
	}

	xfree(buf);

	return NULL;
}

struct html_context {
	IRI
		*base;
	const char
		*encoding;
	buffer_t
		uri_buf;
	int
		sockfd;
	char
		base_allocated,
		encoding_allocated;
};

static void _html_parse(void *context, int flags, const char *dir, const char *attr, const char *val)
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

			if (found && tolower(*dir) == 'b' && !strcasecmp(dir,"base")) {
				// found a <BASE href="...">
				// add it to be downloaded, replace old base
				IRI *iri = iri_parse(val, ctx->encoding);
				if (iri) {
					dprintf(ctx->sockfd, "add uri %s %s\n", ctx->encoding ? ctx->encoding : "-", val);

					if (ctx->base_allocated)
						iri_free(&ctx->base);

					ctx->base = iri;
					ctx->base_allocated = 1;
				}
				return;
			}

			if (!found && !ctx->encoding_allocated) {
				// if we have no encoding yet, read it from META tag, e.g. from
				//   <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
				if (!strcasecmp(dir, "meta")) {
					if (!strcasecmp(attr, "http-equiv") && !strcasecmp(val, "Content-Type"))
						found_content_type = 1;
					else if (found_content_type && !strcasecmp(attr, "content")) {
						http_parse_content_type(val, NULL, &ctx->encoding);
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
			size_t len;

			// sometimes the URIs are surrounded by spaces, we ignore them
			while (isspace(*val))
				val++;

			// skip trailing spaces
			for (len = strlen(val); len && isspace(val[len - 1]); len--)
				;

			if (len > 1 || (len == 1 && *val != '#')) { // ignore e.g. href='#'
				// log_printf("%02X %s %s=%s\n",flags,dir,attr,val);
				if (iri_relative_to_absolute(ctx->base, val, len, &ctx->uri_buf)) {
					// info_printf("%.*s -> %s\n", (int)len, val, ctx->uri_buf.data);
					if (ctx->sockfd >= 0) {
						dprintf(ctx->sockfd, "add uri %s %s\n", ctx->encoding ? ctx->encoding : "-", ctx->uri_buf.data);
					} else {
						JOB *job;

						if ((job = queue_add(blacklist_add(iri_parse(ctx->uri_buf.data, ctx->encoding))))) {
							if (!config.output_document)
								job->local_filename = get_local_filename(job->iri);
						}
					}
				} else {
					err_printf(_("Cannot resolve relative URI %.*s\n"), (int)len, val);
				}
			}
		}
	}
}

// use the xml parser, being prepared that HTML is not XML

void html_parse(int sockfd, const char *data, const char *encoding, IRI *iri)
{
	// create scheme://authority that will be prepended to relative paths
	char uri_sbuf[1024];
	struct html_context context = { .base = iri, .sockfd = sockfd, .encoding = encoding };

	buffer_init(&context.uri_buf, uri_sbuf, sizeof(uri_sbuf));

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	html_parse_buffer(data, _html_parse, &context, HTML_HINT_REMOVE_EMPTY_CONTENT);

	if (context.encoding_allocated)
		xfree(context.encoding);

//		xfree(context.base->connection_part);
	if (context.base_allocated) {
		iri_free(&context.base);
	}

	buffer_deinit(&context.uri_buf);
}

void html_parse_localfile(int sockfd, const char *fname, const char *encoding, IRI *iri)
{
	// create scheme://authority that will be prepended to relative paths
	char uri_sbuf[1024];
	struct html_context context = { .base = iri, .sockfd = sockfd, .encoding = encoding };

	buffer_init(&context.uri_buf, uri_sbuf, sizeof(uri_sbuf));

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	html_parse_file(fname, _html_parse, &context, HTML_HINT_REMOVE_EMPTY_CONTENT);

	if (context.encoding_allocated)
		xfree(context.encoding);

	if (context.base_allocated)
		iri_free(&context.base);

	buffer_deinit(&context.uri_buf);
}

struct css_context {
	IRI
		*base;
	const char
		*encoding;
	buffer_t
		uri_buf;
	int
		sockfd;
	char
		encoding_allocated;
};

static void _css_parse_encoding(void *context, const char *encoding, size_t len)
{
	struct css_context *ctx = context;

	if (!ctx->encoding || (!ctx->encoding_allocated && strncasecmp(ctx->encoding, encoding, len))) {
		ctx->encoding = strndup(encoding, len);
		ctx->encoding_allocated = 1;
		info_printf(_("URI content encoding = '%s'\n"), ctx->encoding);
	}
}

static void _css_parse_uri(void *context, const char *url, size_t len)
{
	struct css_context *ctx = context;

	if (len > 1 || (len == 1 && *url != '#')) {
		// ignore e.g. href='#'
		if (iri_relative_to_absolute(ctx->base, url, len, &ctx->uri_buf)) {
			if (ctx->sockfd >= 0) {
				dprintf(ctx->sockfd, "add uri - %s\n", ctx->uri_buf.data);
			} else {
				JOB *job;

				if ((job = queue_add(blacklist_add(iri_parse(ctx->uri_buf.data, NULL))))) {
					if (!config.output_document)
						job->local_filename = get_local_filename(job->iri);
				}
			}
		} else {
			err_printf(_("Cannot resolve relative URI %.*s\n"), (int)len, url);
		}
	}
}

void css_parse(int sockfd, const char *data, const char *encoding, IRI *iri)
{
	// create scheme://authority that will be prepended to relative paths
	char uri_buf[1024];
	struct css_context context = { .base = iri, .sockfd = sockfd, .encoding = encoding };

	buffer_init(&context.uri_buf, uri_buf, sizeof(uri_buf));

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	css_parse_buffer(data, _css_parse_uri, _css_parse_encoding, &context);

	if (context.encoding_allocated)
		xfree(context.encoding);

	buffer_deinit(&context.uri_buf);
}

void css_parse_localfile(int sockfd, const char *fname, const char *encoding, IRI *iri)
{
	// create scheme://authority that will be prepended to relative paths
	char uri_buf[1024];
	struct css_context context = { .base = iri, .sockfd = sockfd, .encoding = encoding };

	buffer_init(&context.uri_buf, uri_buf, sizeof(uri_buf));

	if (encoding)
		info_printf(_("URI content encoding = '%s'\n"), encoding);

	css_parse_file(fname, _css_parse_uri, _css_parse_encoding, &context);

	if (context.encoding_allocated)
		xfree(context.encoding);

	buffer_deinit(&context.uri_buf);
}

static long long NONNULL_ALL get_file_size(const char *fname)
{
	struct stat st;
	
	if (stat(fname, &st)==0) {
		return st.st_size;
	}

	return 0;
}

static time_t NONNULL_ALL get_file_mtime(const char *fname)
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
		err_printf (_("Failed to set file date: %s\n"), strerror (errno));
}

static void NONNULL((1)) _save_file(HTTP_RESPONSE *resp, const char *fname, int flag)
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
					err_printf(_("Failed to write to STDOUT (%zu, errno=%d)\n"), rc, errno);
			}

			if ((rc = fwrite(resp->body->data, 1, resp->body->length, stdout)) != resp->body->length)
				err_printf(_("Failed to write to STDOUT (%zu, errno=%d)\n"), rc, errno);

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
					err_printf(_("Failed to write file %s (%zd, errno=%d)\n"), fnum ? unique : fname, rc, errno);
			}

			if ((rc = write(fd, resp->body->data, resp->body->length)) != (ssize_t)resp->body->length)
				err_printf(_("Failed to write file %s (%zd, errno=%d)\n"), fnum ? unique : fname, rc, errno);

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
			err_printf(_("File '%s' already there; not retrieving.\n"), fname);
		else
			err_printf(_("Failed to open '%s' (errno=%d)\n"), fname, errno);
	}

	xfree(alloced_fname);
}

static void NONNULL((1)) save_file(HTTP_RESPONSE *resp, const char *fname)
{
	_save_file(resp, fname, O_TRUNC);
}

static void NONNULL((1)) append_file(HTTP_RESPONSE *resp, const char *fname)
{
	_save_file(resp, fname, O_APPEND);
}

//void download_part(int sockfd, JOB *job, PART *part)

void download_part(DOWNLOADER *downloader)
{
	JOB *job = downloader->job;
	PART *part = downloader->part;
	int mirror_index = downloader->id % vec_size(job->mirrors);

	dprintf(downloader->sockfd[1], "sts downloading part...\n");
	do {
		HTTP_RESPONSE *msg;
		MIRROR *mirror = vec_get(job->mirrors, mirror_index);

		mirror_index = (mirror_index + 1) % vec_size(job->mirrors);

		msg = http_get(mirror->iri, part, downloader);
		if (msg) {
			cookie_store_cookies(msg->cookies); // sanitize and store cookies

			if (msg->body) {
				int fd;

				log_printf("# body=%zd/%llu bytes\n", msg->body->length, (unsigned long long)part->length);
				if ((fd = open(job->name, O_WRONLY | O_CREAT, 0644)) != -1) {
					if (lseek(fd, part->position, SEEK_SET) != -1) {
						ssize_t nbytes;

						if ((nbytes = write(fd, msg->body->data, msg->body->length)) == (ssize_t)msg->body->length)
							part->done = 1; // set this when downloaded ok
						else
							err_printf(_("Failed to write %zd bytes (%zd)\n"), msg->body->length, nbytes);
					} else err_printf(_("Failed to lseek to %llu\n"), (unsigned long long)part->position);
					close(fd);
				} else err_printf(_("Failed to write open %s\n"), job->name);

			} else
				log_printf("# empty body\n");

			http_free_response(&msg);
		}
	} while (!part->done);
}

HTTP_RESPONSE *http_get(IRI *iri, PART *part, DOWNLOADER *downloader)
{
	HTTP_CONNECTION *conn;
	HTTP_RESPONSE *resp = NULL;
	VECTOR *challenges = NULL;
//	int max_redirect = 3;

	while (iri) {
		if (downloader->conn && !null_strcmp(downloader->conn->esc_host, iri->host) &&
			downloader->conn->scheme == iri->scheme &&
			!null_strcmp(downloader->conn->port, iri->resolv_port))
		{
			info_printf("reuse connection %s\n", downloader->conn->esc_host);
		} else {
			if (downloader->conn) {
				info_printf("close connection %s\n", downloader->conn->esc_host);
				http_close(&downloader->conn);
			}
			downloader->conn = http_open(iri);
			if (downloader->conn) {
				info_printf("opened connection %s\n", downloader->conn->esc_host);
				downloader->conn->print_response_headers = config.server_response ? 1 : 0;
			}
		}
		conn = downloader->conn;

		if (conn) {
			HTTP_REQUEST *req;

			req = http_create_request(iri, "GET");
			if (config.save_headers)
				req->save_headers = 1;

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
			http_add_header_line(req,
				/*				"Accept-Encoding: gzip\r\n"\
				"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.5) Gecko/20100101 Firefox/10.0.5 Iceweasel/10.0.5\r\n"\
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8\r\n"
				"Accept-Language: en-us,en;q=0.5\r\n");
				 */
				"Accept-Encoding: gzip, deflate\r\n");

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
				IRI *referer = downloader->job->referer;
				char sbuf[256];
				buffer_t buf;

				buffer_init(&buf, sbuf, sizeof(sbuf));

				buffer_strcat(&buf, referer->scheme);
				buffer_memcat(&buf, "://", 3);
				buffer_strcat(&buf, referer->host);
				buffer_memcat(&buf, "/", 1);
				iri_get_escaped_resource(referer, &buf);

				http_add_header(req, "Referer", buf.data);
				buffer_deinit(&buf);
			}

			if (challenges) {
				// There might be more than one challenge, we could select the securest one.
				// For simplicity and testing we just take the first for now.
				// the following adds an Authorization: HTTP header
//				http_add_credentials(req, vec_get(challenges, 0), config.username, config.password);
				http_add_credentials(req, vec_get(challenges, 0), config.http_username, config.http_password);
				http_free_challenges(challenges);
			}

			if (part)
				http_add_header_printf(req, "Range: bytes=%llu-%llu",
					(unsigned long long) part->position, (unsigned long long) part->position + part->length - 1);

			// add cookies
			log_printf("cookies_enabled = %d\n", config.cookies);
			if (config.cookies) {
				const char *cookie_string;

				if ((cookie_string = cookie_create_request_header(iri))) {
					http_add_header(req, "Cookie", cookie_string);
					xfree(cookie_string);
				}
			}

			if (http_send_request(conn, req) == 0) {
				resp = http_get_response(conn, req);
			}

			http_free_request(&req);
		} else break;

		if (!resp) {
			http_close(&downloader->conn);
			break;
		}

		// server doesn't support keep-alive or want us to close the connection
		if (!resp->keep_alive)
			http_close(&downloader->conn);

		if (resp->code == 302 && resp->links && resp->digests)
			break; // 302 with Metalink information

		if (resp->code == 401 && !challenges) { // Unauthorized
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
			char uri_buf_static[1024];
			buffer_t uri_buf;

			cookie_normalize_cookies(iri, resp->cookies);
			cookie_store_cookies(resp->cookies);

			buffer_init(&uri_buf, uri_buf_static, sizeof(uri_buf_static));

			iri_relative_to_absolute(iri, resp->location, strlen(resp->location), &uri_buf);

			dprintf(downloader->sockfd[1], "redirect - %s\n", uri_buf.data);

			buffer_deinit(&uri_buf);
			break;
		}

		http_free_response(&resp);
	}

	return resp;
}

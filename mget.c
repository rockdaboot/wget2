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
	save_file(HTTP_RESPONSE *resp, IRI *iri, int flags),
	append_file(HTTP_RESPONSE *resp, const char *fname),
	html_parse(int sockfd, HTTP_RESPONSE *resp, IRI *iri),
	css_parse(int sockfd, HTTP_RESPONSE *resp, IRI *iri);
HTTP_RESPONSE
	*http_get(IRI *iri, PART *part, DOWNLOADER *downloader);

static DOWNLOADER
	*downloader;
static void
	*downloader_thread(void *p);
static VECTOR
	*blacklist,
	*hosts;
static int
	terminate;

static int in_blacklist(const char *uri)
{
	const char *p = uri;

	while (*p && !iri_isgendelim(*p))
		p++;

	if (*p == ':') {
		// URI has a scheme, check if we support that scheme
		int it;

		for (it = 0; iri_schemes[it]; it++) {
			if (!strncasecmp(uri, iri_schemes[it], p-uri))
				return vec_find(blacklist, uri) >= 0;
		}
	}

	return 0;
}

static int blacklist_add(const char *uri)
{
	if (in_blacklist(uri))
		return 0;

	if (!blacklist)
		blacklist = vec_create(128, -2, (int(*)(const void *, const void *))strcmp);

	//	info_printf("Add to blacklist: %s\n",uri);
	vec_insert_sorted(blacklist, uri, strlen(uri) + 1);
	return 1;
}

static int schedule_download(JOB *job, PART *part)
{
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

static void host_add(const char *host)
{
	if (!hosts)
		hosts = vec_create(4, 4, (int(*)(const void *, const void *))strcasecmp);

	vec_insert_sorted(hosts, host, strlen(host) + 1);
}

static void nop(int sig)
{
	if (sig == SIGTERM) {
		terminate = 1; // set global termination flag
	} else if (sig == SIGINT) {
		abort();
	}
}

//static void normalize_path(char *path);

int main(int argc, const char *const *argv)
{
	int n, rc, maxfd, nfds;
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
		if (blacklist_add(argv[n])) {
			// argv[n] is not in blacklist, add it to the job queue
			if (config.recursive && !config.span_hosts) {
				// only download content from hosts given on the command line
				JOB *job = queue_add(iri_parse(argv[n]));
				host_add(job->iri->host);
			} else {
				queue_add(iri_parse(argv[n]));
			}
		}
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

	while (queue_not_empty()) {
		FD_ZERO(&rset);
		for (maxfd = n = 0; n < config.num_threads; n++) {
			FD_SET(downloader[n].sockfd[0], &rset);
			if (downloader[n].sockfd[0] > maxfd)
				maxfd = downloader[n].sockfd[0];
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

						if (queue_get(&downloader[n].job, &downloader[n].part))
							dprintf(downloader[n].sockfd[0], "go\n");
					} else if (!strncmp(buf, "chunk ", 6)) {
						if (!strncasecmp(buf + 6, "mirror ", 7)) {
							MIRROR mirror;

							if (!job->mirrors)
								job->mirrors = vec_create(4, 4, NULL);

							memset(&mirror, 0, sizeof(MIRROR));
							pos = 0;
							if (sscanf(buf + 13, "%2s %6d %n", mirror.location, &mirror.priority, &pos) >= 2 && pos) {
								mirror.iri = iri_parse(buf + 13 + pos);
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
					} else if (!strncmp(buf, "add uri ", 8)) {
						if (blacklist_add(buf + 8)) {
							// URI is not in blacklist, add it to the job queue
							IRI *iri = iri_parse(buf + 8);
							if (config.recursive && !config.span_hosts) {
								// only download content from given hosts
								if (iri->host && vec_find(hosts, iri->host) >= 0) {
									job = queue_add(iri);
									schedule_download(job, NULL);
								} else
									iri_free(&iri);
							} else {
								job = queue_add(iri);
								schedule_download(job, NULL);
							}
						}
					}
				}
				nfds--;
			}
		}
	}

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

	if (config.debug) {
		for (n = 0; n < vec_size(blacklist); n++) {
			char *host = vec_get(blacklist, n);
			info_printf("blacklist[%d] %s\n", n, host);
		}
	}

	// freeing to avoid disguising valgrind output
	tcp_set_dns_caching(0); // frees DNS cache
	ssl_deinit();
	queue_free();
	vec_free(&blacklist);
	vec_free(&hosts);
	xfree(downloader);

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
							dprintf(sockfd, "add uri %s\n", metalink->uri);
							goto ready;
						} else if (top_link) {
							// no metalink4 description found, create a new job
							dprintf(sockfd, "add uri %s\n", top_link->uri);
							goto ready;
						}
					}

					if (resp->content_type) {
						if (!strcasecmp(resp->content_type, "application/metalink4+xml")) {
							dprintf(sockfd, "sts get metalink info\n");
							// save_file(resp, job->iri, HTTP_FLG_USE_FILE);
							metalink4_parse(sockfd, resp);
							goto ready;
						}
					}

					if (resp->location) {
						// we have been forwarded to another location
						// update job with new location
						iri_free(&job->iri);
						job->iri = iri_parse(resp->location);
						resp->location = NULL;
					}

					if (resp->code == 200) {
						if (config.recursive && resp->content_type) {
							info_printf("content-type: %s\n", resp->content_type);
							if (!strcasecmp(resp->content_type, "text/html")) {
								html_parse(sockfd, resp, job->iri);
							} else if (!strcasecmp(resp->content_type, "application/xhtml+xml")) {
								// xml_parse(sockfd, resp, job->iri);
							} else if (!strcasecmp(resp->content_type, "text/css")) {
								css_parse(sockfd, resp, job->iri);
							}
							if (!config.spider) {
								if (config.output_document)
									append_file(resp, config.output_document);
								else
									save_file(resp, job->iri, HTTP_FLG_USE_PATH);
							}
						} else if (!config.spider) {
							if (config.output_document)
								append_file(resp, config.output_document);
							else
								save_file(resp, job->iri, HTTP_FLG_USE_FILE);
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
		*tag;
	buffer_t
		uri_buf;
	int
		sockfd;
	char
		base_allocated;
};

static void _html_parse(void *context, int flags, UNUSED const char *dir, const char *attr, const char *val)
{
	struct html_context *ctx = context;

	if ((flags &= XML_FLG_ATTRIBUTE) && val) {
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

			if (found && (*dir == 'b' || *dir == 'B') && !strcasecmp(dir,"base")) {
				// found a <BASE href="...">
				// add it to be downloaded, replace old base
				IRI *iri = iri_parse(val);
				if (iri) {
					dprintf(ctx->sockfd, "add uri %s\n", val);

					if (ctx->base_allocated)
						iri_free(&ctx->base);

					ctx->base = iri;
					ctx->base_allocated = 1;
				}
				return;
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

			if (len > 1 || (len == 1 && *val != '#')) {
				info_printf("%02X %s %s=%s\n",flags,dir,attr,val);
				// ignore e.g. href='#'
				iri_relative_to_absolute(ctx->base, ctx->tag, val, len, &ctx->uri_buf);
				info_printf("  %s -> %s\n", ctx->base->uri, ctx->uri_buf.data);
				dprintf(ctx->sockfd, "add uri %s\n", ctx->uri_buf.data);
			}
		}
	}
}

// use the xml parser, being prepared that HTML is not XML

void html_parse(int sockfd, HTTP_RESPONSE *resp, IRI *iri)
{
	// create scheme://authority that will be prepended to relative paths
	char tag_sbuf[1024];
	char uri_sbuf[1024];
	buffer_t tag;
	struct html_context context = { .base = iri, .sockfd = sockfd };

	buffer_init(&tag, tag_sbuf, sizeof(tag_sbuf));
	context.tag = iri_get_connection_part(iri, &tag);

	buffer_init(&context.uri_buf, uri_sbuf, sizeof(uri_sbuf));

	html_parse_buffer(resp->body->data, _html_parse, &context, HTML_HINT_REMOVE_EMPTY_CONTENT);

	if (context.base_allocated)
		iri_free(&context.base);

	buffer_deinit(&context.uri_buf);
	buffer_deinit(&tag);
}

struct css_context {
	IRI
		*iri;
	const char
		*tag;
	buffer_t
		uri_buf;
	int
		sockfd;
};

static void _css_parse(void *context, const char *url, size_t len)
{
	struct html_context *ctx = context;

	if (len > 1 || (len == 1 && *url != '#')) {
		// ignore e.g. href='#'
		iri_relative_to_absolute(ctx->base, ctx->tag, url, len, &ctx->uri_buf);
		dprintf(ctx->sockfd, "add uri %s\n", ctx->uri_buf.data);
	}
	// add_uri(ctx->sockfd, ctx->iri, ctx->tag, url, len);
}

void css_parse(int sockfd, HTTP_RESPONSE *resp, IRI *iri)
{
	// create scheme://authority that will be prepended to relative paths
	char tag_sbuf[1024];
	char uri_buf[1024];
	buffer_t tag;
	struct css_context context = { .iri = iri, .sockfd = sockfd };

	buffer_init(&tag, tag_sbuf, sizeof(tag_sbuf));
	context.tag = iri_get_connection_part(iri, &tag);

	buffer_init(&context.uri_buf, uri_buf, sizeof(uri_buf));

	css_parse_buffer(resp->body->data, _css_parse, &context);

	buffer_deinit(&context.uri_buf);
	buffer_deinit(&tag);
}

void append_file(HTTP_RESPONSE *resp, const char *fname)
{
	int fd;

	info_printf("append to '%s'\n", fname);

	if (!strcmp(fname,"-")) {
		size_t rc;
		if ((rc = fwrite(resp->body->data, 1, resp->body->length, stdout)) != resp->body->length)
			err_printf(_("Failed to write to STDOUT (%zu, errno=%d)\n"), rc, errno);
	}
	else if ((fd = open(fname, O_WRONLY | O_APPEND | O_CREAT, 0644)) != -1) {
		ssize_t rc;
		if ((rc = write(fd, resp->body->data, resp->body->length)) != (ssize_t)resp->body->length)
			err_printf(_("Failed to write file %s (%zd, errno=%d)\n"), fname, rc, errno);
		close(fd);
	} else
		err_printf(_("Failed to open '%s' (errno=%d)\n"), fname, errno);
}

void save_file(HTTP_RESPONSE *resp, IRI *iri, int flags)
{
	int fd, n = 0;

	if (flags & HTTP_FLG_USE_FILE) {
		// create the file within the current directory
		const char *iri_fname;
		char *fname;
		size_t l1, l2, l3;

		if (iri->path) {
			if ((iri_fname = strrchr(iri->path, '/')))
				iri_fname++;
			else
				iri_fname = iri->path;
		} else
			iri_fname = NULL;

		// construct filename on the stack
		l1 = iri_fname ? strlen(iri_fname) : 0;
		l2 = iri->query ? strlen(iri->query) + 1 : 0;
		l3 = iri->fragment ? strlen(iri->fragment) + 1 : 0;

		if (l1 + l2 + l3 == 0) {
			// no filename
			iri_fname = "index.html";
			l1 = 10; // l1=strlen(iri_fname);
		}

		fname = alloca(l1 + l2 + l3 + 1);

		if (iri_fname) {
			strcpy(fname + n, iri_fname);
			n += l1;
		}
		if (iri->query) {
			fname[n++] = '?';
			strcpy(fname + n, iri->query);
			n += l2;
		}
		if (iri->fragment) {
			fname[n++] = '#';
			strcpy(fname + n, iri->fragment);
			n += l3;
		}

		info_printf("saving '%s'\n", fname);
		if ((fd = open(fname, O_WRONLY | O_TRUNC | O_CREAT, 0644)) != -1) {
			ssize_t rc;
			if ((rc = write(fd, resp->body->data, resp->body->length)) != (ssize_t)resp->body->length)
				err_printf(_("Failed to write file %s (%zd, errno=%d)\n"), fname, rc, errno);
			close(fd);
		} else
			err_printf(_("Failed to open '%s' (errno=%d)\n"), fname, errno);
	} else if (flags & HTTP_FLG_USE_PATH) {
		// create the complete path
		const char *p1, *p2;
		//		int hostlen=strlen(iri->host);
		char
			dir[strlen(iri->host)
			+(iri->path ? strlen(iri->path) + 1 : 0)
			+(iri->query ? strlen(iri->query) + 1 : 0)
			+(iri->fragment ? strlen(iri->fragment) + 1 : 0)
			+ 11 + 1]; // 11 extra for '/index.html'

		if (mkdir(iri->host, 0755) != 0 && errno != EEXIST) {
			err_printf_exit(_("Failed to make directory '%s'\n"), iri->host);
			return;
		}

		n = snprintf(dir, sizeof(dir), "%s", iri->host);

		if (iri->path) {
			for (p1 = iri->path; *p1 && (p2 = strchr(p1, '/')); p1 = p2 + 1) {
				n += snprintf(dir + n, sizeof(dir) - n, "/%.*s", (int)(p2 - p1), p1);

				// relative paths should have been normalized earlier,
				// but for security reasons, don't trust myself...
				if (*p1 == '.' && !strncmp(p1, "..", 2))
					err_printf_exit(_("Internal error: Unexpected relative path: '%s'\n"), iri->path);

				if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
					err_printf(_("Failed to make directory '%s'\n"), dir);
					return;
				}
			}
			if (*p1)
				n += snprintf(dir + n, sizeof(dir) - n, "/%s", p1);
			else
				n += snprintf(dir + n, sizeof(dir) - n, "/index.html");
		} else if (!iri->query && !iri->fragment)
			n += snprintf(dir + n, sizeof(dir) - n, "/index.html");

		if (iri->query)
			n += snprintf(dir + n, sizeof(dir) - n, "?%s", iri->query);
		if (iri->fragment)
			n += snprintf(dir + n, sizeof(dir) - n, "#%s", iri->fragment);

		info_printf("saving '%s'\n", dir);
		if ((fd = open(dir, O_WRONLY | O_TRUNC | O_CREAT, 0644)) != -1) {
			ssize_t rc;
			if ((rc = write(fd, resp->body->data, resp->body->length)) != (ssize_t)resp->body->length)
				err_printf(_("Failed to write file %s (%zd, errno=%d)\n"), dir, rc, errno);
			close(fd);
		} else
			err_printf(_("Failed to open '%s' (errno=%d)\n"), dir, errno);
	}
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
	IRI *use_iri = iri;
	HTTP_CONNECTION *conn;
	HTTP_RESPONSE *resp = NULL;
	int max_redirect = 3;
	const char *location = NULL;
	char uri_buf_static[1024];
	buffer_t uri_buf;

	buffer_init(&uri_buf, uri_buf_static, sizeof(uri_buf_static));

	while (use_iri) {
		if (!downloader->conn) {
			downloader->conn = http_open(use_iri);
			if (downloader->conn)
				info_printf("opened connection %s\n", downloader->conn->host);
		} else if (!null_strcasecmp(downloader->conn->host, use_iri->host) &&
			downloader->conn->scheme == use_iri->scheme &&
			!null_strcasecmp(downloader->conn->port, use_iri->port))
		{
			info_printf("reuse connection %s\n", downloader->conn->host);
		} else {
			info_printf("close connection %s\n", downloader->conn->host);
			http_close(&downloader->conn);
			downloader->conn = http_open(use_iri);
			if (downloader->conn)
				info_printf("opened connection %s\n", downloader->conn->host);
		}
		conn = downloader->conn;

		if (conn) {
			HTTP_REQUEST *req;

			req = http_create_request(use_iri, "GET");

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
				"Accept-Encoding: gzip\r\n");

			http_add_header_line(req, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");

//			if (config.spider && !config.recursive)
//				http_add_header_if_modified_since(time(NULL));
//				http_add_header_line(req, "If-Modified-Since: Wed, 29 Aug 2012 00:00:00 GMT\r\n");

			if (config.user_agent)
				http_add_header(req, "User-Agent", config.user_agent);

			// if (config.keep_alive)
			http_add_header_line(req, "Connection: keep-alive\r\n");

			if (part)
				http_add_header_printf(req, "Range: bytes=%llu-%llu",
					(unsigned long long) part->position, (unsigned long long) part->position + part->length - 1);

			if (http_send_request(conn, req) == 0) {
				resp = http_get_response(conn, NULL);
			}

			http_free_request(&req);
			// http_close(&conn);
		} else break;

		xfree(location);

		if (!resp) {
			http_close(&downloader->conn);
			break;
		}

		// server doesn't support keep-alive or want us to close the connection
		if (!resp->keep_alive)
			http_close(&downloader->conn);

		if (--max_redirect < 0) {
			if (resp->location) // end of forwarding chain not reached
				http_free_response(&resp);
			break;
		}

		// 304 Not Modified
		if (resp->code / 100 == 2 || resp->code / 100 >= 4 || resp->code == 304)
			break; // final response

		if (resp->code == 302 && resp->links && resp->digests)
			break; // 302 with Metalink information

		if (resp->location) {
			char tag_sbuf[1024];
			buffer_t tag_buf;
			const char *tag = iri_get_connection_part(use_iri, buffer_init(&tag_buf, tag_sbuf, sizeof(tag_sbuf)));

			iri_relative_to_absolute(
				use_iri, tag, resp->location, strlen(resp->location), &uri_buf);

			location = resp->location;
			resp->location = NULL;

			if (use_iri != iri)
				iri_free(&use_iri);

			use_iri = iri_parse(uri_buf.data);

			buffer_deinit(&uri_buf);
		} else {
			if (use_iri != iri)
				iri_free(&use_iri);
		}

		http_free_response(&resp);
	}

	if (use_iri && use_iri != iri)
		iri_free(&use_iri);

	return resp;
}

/*
 * Copyright(c) 2013-2014 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Test suite function library
 *
 * Changelog
 * 16.01.2013  Tim Ruehsen  created
 *
 * To create the X.509 stuff, I followed the instructions at
 *   gnutls.org/manual/html_node/gnutls_002dserv-Invocation.html
 *
 */

#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <utime.h>
#include <dirent.h>
#include <c-ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <wget.h>
#include "libtest.h"

#ifdef WITH_MICROHTTPD
	#include <microhttpd.h>
#endif

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>

static wget_thread_t
	https_server_tid,
	ftp_server_tid,
	ftps_server_tid;
static int
	http_server_port,
	https_server_port,
	ftp_server_port,
	ftps_server_port,
	ftps_implicit,
	keep_tmpfiles;
static volatile sig_atomic_t
	terminate;
/*static const char
	*response_code = "200 Dontcare",
	*response_body = "";
static WGET_VECTOR
	*response_headers; */
static wget_vector_t
	*request_urls;
static wget_test_url_t
	*urls;
static size_t
	nurls;
static wget_test_ftp_io_t
	*ios;
static size_t
	nios;
static int
	ios_ordered;
static char
	tmpdir[128];
static const char
	*server_hello;
static char
	server_send_content_length = 1;

#ifdef WITH_MICROHTTPD
// MHD_Daemon instance
struct MHD_Daemon
	*httpdaemon;
#endif

// for passing URL query string
struct query_string {
	wget_buffer_t
		*params;
	int
		it;
};

static void sigterm_handler(int sig G_GNUC_WGET_UNUSED)
{
	terminate = 1;
}

static void *_http_server_thread(void *ctx)
{
	wget_tcp_t *tcp=NULL, *parent_tcp = ctx;
	wget_test_url_t *url = NULL;
	char buf[4096], method[32], request_url[256], tag[64], value[256], *p;
	ssize_t from_bytes, to_bytes, n;
	size_t nbytes, body_len, request_url_length;
	unsigned it;
	int byterange, authorized;
	time_t modified;

#ifdef _WIN32
	signal(SIGTERM, sigterm_handler);
#else
	sigaction(SIGTERM, &(struct sigaction) { .sa_handler = sigterm_handler }, NULL);
#endif

	while (!terminate) {
		wget_tcp_deinit(&tcp);

		wget_info_printf("[SERVER] accept...\n");
		if ((tcp = wget_tcp_accept(parent_tcp))) {
			wget_info_printf("[SERVER] accepted\n");
			authorized = 0;

			nbytes = 0;
			while ((n = wget_tcp_read(tcp, buf + nbytes, sizeof(buf) - 1 - nbytes)) > 0) {
				nbytes += n;
				buf[nbytes]=0;
				wget_info_printf(_("[SERVER] got %zd bytes (total %zu)\n"), n, nbytes);
				if (strstr(buf,"\r\n\r\n"))
					break;
			}
			wget_info_printf(_("[SERVER] total %zd bytes (total %zu) (errno=%d)\n"), n, nbytes, errno);

			if (nbytes > 0) {
				if (sscanf(buf, "%31s %255s", method, request_url) !=2) {
					wget_tcp_printf(tcp, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
					continue;
				}

				byterange = from_bytes = to_bytes = 0;
				modified = 0;

				for (p = strstr(buf, "\r\n"); p && sscanf(p, "\r\n%63[^:]: %255[^\r]", tag, value) == 2; p = strstr(p + 2, "\r\n")) {
					if (!wget_strcasecmp_ascii(tag, "Range")) {
						if ((byterange = sscanf(value, "bytes=%zd-%zd", &from_bytes, &to_bytes)) < 1)
							byterange = 0;
					}
					else if (url && !wget_strcasecmp_ascii(tag, "Authorization")) {
						const char *auth_scheme, *s;

						s=wget_http_parse_token(value, &auth_scheme);
						while (c_isblank(*s)) s++;

						if (!wget_strcasecmp_ascii(auth_scheme, "basic")) {
							const char *encoded = wget_base64_encode_printf_alloc("%s:%s", url->auth_username, url->auth_password);

							wget_error_printf("Auth check '%s' <-> '%s'\n", encoded, s);
							if (!strcmp(encoded, s))
								authorized = 1;

							wget_xfree(encoded);
						}

						wget_xfree(auth_scheme);
					}
					else if (!wget_strcasecmp_ascii(tag, "If-Modified-Since")) {
						modified = wget_http_parse_full_date(value);
						wget_info_printf("modified = %ld\n", modified);
					}
				}

				url = NULL;
				request_url_length = strlen(request_url);

				if (request_url[request_url_length - 1] == '/') {
					// access a directory
					for (it = 0; it < nurls; it++) {
						if (!strcmp(request_url, urls[it].name) ||
							(!strncmp(request_url, urls[it].name, request_url_length) &&
							!strcmp(urls[it].name + request_url_length, "index.html")))
						{
							url = &urls[it];
							break;
						}
					}
				} else {
					// access a file
					for (it = 0; it < nurls; it++) {
						// printf("%s %s\n", request_url, urls[it].name);
						if (!strcmp(request_url, urls[it].name)) {
							url = &urls[it];
							break;
						}
					}
				}

				if (!url) {
					wget_tcp_printf(tcp, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
					continue;
				}

				if (url->auth_method && !authorized) {
					if (!wget_strcasecmp_ascii(url->auth_method, "basic"))
						wget_tcp_printf(tcp,
							"HTTP/1.1 401 Unauthorized\r\n" \
							"WWW-Authenticate: %s realm=\"Protected Page\"\r\n" \
							"Connection: close\r\n\r\n",
							url->auth_method);
					else
						wget_error_printf(_("Unknown authentication scheme '%s'\n"), url->auth_method);

					continue;
				}

				if (modified && url->modified<=modified) {
					wget_tcp_printf(tcp,"HTTP/1.1 304 Not Modified\r\n\r\n");
					continue;
				}

				if (byterange == 1) {
					to_bytes = strlen(url->body) - 1;
				}
				if (byterange) {
					if (from_bytes > to_bytes || from_bytes >= (int)strlen(url->body)) {
						wget_tcp_printf(tcp, "HTTP/1.1 416 Range Not Satisfiable\r\nConnection: close\r\n\r\n");
						continue;
					}

					// create response
					body_len = to_bytes - from_bytes + 1;
					nbytes = snprintf(buf, sizeof(buf), "HTTP/1.1 206 Partial Content\r\n");
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "Content-Length: %zu\r\n", body_len);
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "Accept-Ranges: bytes\r\n");
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "Content-Range: %zd-%zd/%zu\r\n", from_bytes, to_bytes, body_len);
					for (it = 0; it < countof(url->headers) && url->headers[it]; it++) {
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s\r\n", url->headers[it]);
					}
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "\r\n");
					if (!strcmp(method, "GET") || !strcmp(method, "POST"))
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%.*s", (int)body_len, url->body + from_bytes);
				} else {
					// create response
					body_len = strlen(url->body ? url->body : "");
					nbytes = snprintf(buf, sizeof(buf), "HTTP/1.1 %s\r\n", url->code ? url->code : "200 OK");
					if (server_send_content_length)
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "Content-Length: %zu\r\n", body_len);
					for (it = 0; it < countof(url->headers) && url->headers[it]; it++) {
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s\r\n", url->headers[it]);
					}
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "\r\n");
					if (!strcmp(method, "GET") || !strcmp(method, "POST"))
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s", url->body ? url->body : "");
				}

				// send response
				wget_tcp_write(tcp, buf, nbytes);
			}
		} else if (!terminate)
			wget_error_printf(_("Failed to get connection (%d)\n"), errno);
	}

	wget_tcp_deinit(&parent_tcp);

	wget_info_printf("[SERVER] stopped\n");
	return NULL;
}

#ifdef WITH_MICROHTTPD
static char *_scan_directory(const char* data)
{
	char *path = strchr(data, '/');
	if (path != 0) {
		return path;
	}
	else
		return NULL;
}

static int _print_query_string(void *cls, enum MHD_ValueKind kind,
							const char *key,
							const char *value)
{
	struct query_string *query = cls;

	if (key && query->it == 0) {
		wget_buffer_strcpy(query->params, "?");
		wget_buffer_strcat(query->params, key);
		if (value) {
			wget_buffer_strcat(query->params, "=");
			wget_buffer_strcat(query->params, value);
		}
	}
	if (key && query->it != 0) {
		wget_buffer_strcat(query->params, "&");
		wget_buffer_strcat(query->params, key);
		if (value) {
			wget_buffer_strcat(query->params, "=");
			wget_buffer_strcat(query->params, value);
		}
	}

	query->it++;
    return MHD_YES;
}

static int _answer_to_connection(void *cls,
					struct MHD_Connection *connection,
					const char *url,
					const char *method,
					const char *version,
					const char *upload_data, size_t *upload_data_size, void **con_cls)
{
	struct MHD_Response *response;
	struct query_string query;
	int ret;

	// get query string
	query.params = wget_buffer_alloc(1024);
	query.it = 0;
	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, &_print_query_string, &query);

	// append query string into URL
	wget_buffer_t *url_full = wget_buffer_alloc(1024);
	wget_buffer_strcpy(url_full, url);
	if (query.params->data)
		wget_buffer_strcat(url_full, query.params->data);
	wget_buffer_free(&query.params);

	// it1 = iteration for urls data
	unsigned int it1, found = 0;
	for (it1 = 0; it1 < nurls; it1++) {
		// create default page for directory without index page
		char *dir = _scan_directory(url_full->data + 1);
		if (dir != 0 && !strcmp(dir, "/"))
			wget_buffer_strcat(url_full, "index.html");

		if (!strcmp(url_full->data, urls[it1].name))
		{
			response = MHD_create_response_from_buffer(strlen(urls[it1].body),
					(void *) urls[it1].body, MHD_RESPMEM_MUST_COPY);
			ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

			// add available headers
			if (*urls[it1].headers) {
				// it2 = iteration for headers
				for (unsigned int it2 = 0; urls[it1].headers[it2] != NULL; it2++) {
					const char *header = urls[it1].headers[it2];
					if (header) {
						const char *header_value = strchr(header, ':');
						const char *header_key = wget_strmemdup(header, header_value - header);
						MHD_add_response_header(response, header_key, header_value + 2);
						wget_xfree(header_key);
					}
				}
			}

			it1 = nurls;
			found = 1;
		}
	}

	// 404 with empty "body"
	if (found == 0) {
		response = MHD_create_response_from_buffer(0, (void *) "", MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
	}

	wget_buffer_free(&url_full);
	MHD_destroy_response(response);
	return ret;
}

static void _http_server_stop(void)
{
	MHD_stop_daemon(httpdaemon);
}

static int _http_server_start(void)
{
	int port_num = 0;

	httpdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
				port_num, NULL, NULL, &_answer_to_connection, NULL, NULL,
				MHD_OPTION_END);

	if (!httpdaemon)
		return 1;

	// get open random port number
	if (0) {}
#if MHD_VERSION >= 0x00095501
	else if (MHD_is_feature_supported(MHD_FEATURE_AUTODETECT_BIND_PORT != MHD_NO))
	{
		const union MHD_DaemonInfo *dinfo;
		dinfo = MHD_get_daemon_info(httpdaemon, MHD_DAEMON_INFO_BIND_PORT);
		if (dinfo == NULL || dinfo->port == 0)
		{
			return 1;
		}
		port_num = (int)dinfo->port;
		http_server_port = port_num;
	}
#endif /* MHD_VERSION >= 0x00095501 */
	else
	{
		const union MHD_DaemonInfo *dinfo;
		MHD_socket sock_fd;
		dinfo = MHD_get_daemon_info(httpdaemon, MHD_DAEMON_INFO_LISTEN_FD);

		if (dinfo == NULL)
		{
			return 1;
		}
		sock_fd = dinfo->listen_fd;

		struct sockaddr_storage addr_store;
		struct sockaddr *addr = (struct sockaddr *)&addr_store;
		socklen_t addr_len = sizeof(addr_store);
		char s_port[NI_MAXSERV];

		// get automatic retrieved port number
		if (getsockname(sock_fd, addr, &addr_len) == 0) {
			if (getnameinfo(addr, addr_len, NULL, 0, s_port, sizeof(s_port), NI_NUMERICSERV) == 0)
				port_num = atoi(s_port);
				http_server_port = port_num;
		}

	}

	return 0;
}
#endif

static void *_ftp_server_thread(void *ctx)
{
	wget_tcp_t *tcp = NULL, *parent_tcp = ctx, *pasv_parent_tcp = NULL, *pasv_tcp = NULL;
	char buf[4096];
	ssize_t nbytes;
	int pasv_port, found;
	unsigned io_pos;

#ifdef _WIN32
	signal(SIGTERM, sigterm_handler);
#else
	sigaction(SIGTERM, &(struct sigaction) { .sa_handler = sigterm_handler }, NULL);
#endif

	while (!terminate) {
		wget_tcp_deinit(&tcp);
		wget_tcp_deinit(&pasv_tcp);
		wget_tcp_deinit(&pasv_parent_tcp);

		if ((tcp = wget_tcp_accept(parent_tcp))) {
			io_pos = 0;

			if (server_hello)
				wget_tcp_printf(tcp, "%s\r\n", server_hello);

			// as a quick hack, just assume that each line comes in one packet
			while ((nbytes = wget_tcp_read(tcp, buf, sizeof(buf)-1)) > 0) {
				buf[nbytes] = 0;

				while (--nbytes >= 0 && (buf[nbytes] == '\r' || buf[nbytes] == '\n'))
					buf[nbytes] = 0;

				wget_debug_printf("### Got: '%s'\n", buf);

				found = 0;
				if (ios_ordered) {
					if (!strcmp(buf, ios[io_pos].in))
						found = 1;
				} else {
					for (io_pos = 0; io_pos < nios; io_pos++) {
						if (!strcmp(buf, ios[io_pos].in)) {
							found = 1;
							break;
						}
					}
				}
				if (!found) {
					wget_error_printf(_("Unexpected input: '%s'\n"), buf);
					wget_tcp_printf(tcp, "500 Unknown command\r\n");
					continue;
				}

				if (!strncmp(buf, "AUTH", 4)) {
					// assume TLS auth type
					wget_tcp_printf(tcp, "%s\r\n", ios[io_pos].out);
					if (atoi(ios[io_pos].out)/100 == 2)
						wget_tcp_tls_start(tcp);
					io_pos++;
					continue;
				}

				if (!strncmp(buf, "PASV", 4) || !strncmp(buf, "EPSV", 4)) {
					// init FTP PASV/EPSV socket
					// we ignore EPSV address type here, we listen on IPv4 and IPv6 anyways
					pasv_parent_tcp=wget_tcp_init();
					wget_tcp_set_timeout(pasv_parent_tcp, -1); // INFINITE timeout
					if (!strncmp(buf, "EPSV", 4)) {
						switch (atoi(buf+4)) {
							case 1: wget_tcp_set_family(pasv_parent_tcp, WGET_NET_FAMILY_IPV4); break;
							case 2: wget_tcp_set_family(pasv_parent_tcp, WGET_NET_FAMILY_IPV6); break;
							default: wget_tcp_set_family(pasv_parent_tcp, WGET_NET_FAMILY_ANY); break;
						}
					}
					if (wget_tcp_listen(pasv_parent_tcp, "localhost", 0, 5) != 0) {
						wget_tcp_printf(tcp, "500 failed to open port\r\n");
						break;
					}
					pasv_port = wget_tcp_get_local_port(pasv_parent_tcp);

					const char *src = ios[io_pos].out;
					char *response = wget_malloc(strlen(src) + 32 + 1);
					char *dst = response;

					while (*src) {
						if (*src == '{') {
							if (!strncmp(src, "{{pasvdata}}", 12)) {
								if (!strncmp(buf, "EPSV", 4))
									dst += sprintf(dst, "(|||%d|)", pasv_port);
								else
									dst += sprintf(dst, "(127,0,0,1,%d,%d)", pasv_port / 256, pasv_port % 256);
								src += 12;
								continue;
							}
						}
						*dst++ = *src++;
					}
					*dst = 0;

					wget_tcp_printf(tcp, "%s\r\n", response);
					wget_xfree(response);

					if (!(pasv_tcp = wget_tcp_accept(pasv_parent_tcp))) {
						wget_error_printf(_("Failed to get PASV connection\n"));
						break;
					}
				} else {
					wget_tcp_printf(tcp, "%s\r\n", ios[io_pos].out);
				}

				if (ios[io_pos].send_url && pasv_tcp) {
					// send data
					wget_tcp_printf(pasv_tcp, "%s", ios[io_pos].send_url->body);
					wget_tcp_deinit(&pasv_tcp);
					wget_tcp_printf(tcp, "226 Transfer complete\r\n");
				}

				io_pos++;
			}
		} else if (!terminate)
			wget_error_printf(_("Failed to get connection (%d)\n"), errno);
	}

	wget_tcp_deinit(&parent_tcp);

	return NULL;
}

#if defined __CYGWIN__
// Using opendir/readdir loop plus unlink() has a race condition
// with CygWin. Not sure if this also happens on other systems as well.
// Since we don't have valgrind, we can use system() without issues.
static void _remove_directory(const char *dirname)
{
	char cmd[strlen(dirname) + 16];

	snprintf(cmd, sizeof(cmd), "rm -rf %s", dirname);
	system(cmd);
}
static void _empty_directory(const char *dirname)
{
	_remove_directory(dirname);

	if (mkdir(dirname, 0755) != 0)
		wget_error_printf_exit(_("Failed to re-create directory (%d)\n"), errno);
}
#else
// To reduce the verbosity of 'valgrind --trace-children=yes' output,
//   we avoid system("rm -rf ...") calls.
static void _remove_directory(const char *dirname);
static void _empty_directory(const char *dirname)
{
	DIR *dir;
	struct dirent *dp;
	size_t dirlen = strlen(dirname);

	if ((dir = opendir(dirname))) {
		while ((dp = readdir(dir))) {
			if (*dp->d_name == '.' && (dp->d_name[1] == 0 || (dp->d_name[1] == '.' && dp->d_name[2] == 0)))
				continue;

			char fname[dirlen + 1 + strlen(dp->d_name) + 1];
			snprintf(fname, sizeof(fname), "%s/%s", dirname, dp->d_name);

			if (unlink(fname) == -1) {
				// in case fname is a directory glibc returns EISDIR but correct POSIX value would be EPERM.
				// MinGW + Wine returns EACCESS here.
				if (errno == EISDIR || errno == EPERM || errno == EACCES)
					_remove_directory(fname);
				else
					wget_error_printf(_("Failed to unlink %s (%d)\n"), fname, errno);
			}
		}

		closedir(dir);

		wget_debug_printf("Removed test directory '%s'\n", dirname);
	} else if (errno != ENOENT)
		wget_error_printf(_("Failed to opendir %s (%d)\n"), dirname, errno);
}

static void _remove_directory(const char *dirname)
{
	_empty_directory(dirname);
	if (rmdir(dirname) == -1 && errno != ENOENT)
		wget_error_printf(_("Failed to rmdir %s (%d)\n"), dirname, errno);
}
#endif

void wget_test_stop_server(void)
{
//	wget_vector_free(&response_headers);
	wget_vector_free(&request_urls);

	for (wget_test_url_t *url = urls; url < urls + nurls; url++) {
		if (url->body_alloc) {
			wget_xfree(url->body);
			url->body_alloc = 0;
		}

		for (size_t it = 0; it < countof(url->headers); it++) {
			if (url->header_alloc[it]) {
				wget_xfree(url->headers[it]);
				url->header_alloc[it] = 0;
			}
		}
	}

	// free resources - needed for valgrind testing
	terminate = 1;
//	pthread_kill(http_server_tid, SIGTERM);
//	pthread_kill(https_server_tid, SIGTERM);
//	pthread_kill(ftp_server_tid, SIGTERM);
//	if (ftps_implicit)
//		pthread_kill(ftps_server_tid, SIGTERM);

	wget_thread_cancel(https_server_tid);
	wget_thread_cancel(ftp_server_tid);
	if (ftps_implicit)
		wget_thread_cancel(ftps_server_tid);
//	wget_thread_join(http_server_tid);
//	wget_thread_join(https_server_tid);
//	wget_thread_join(ftp_server_tid);
//	if (ftps_implicit)
//		wget_thread_join(ftps_server_tid);

	if (chdir("..") != 0)
		wget_error_printf(_("Failed to chdir ..\n"));

	if (!keep_tmpfiles)
		_remove_directory(tmpdir);

	wget_global_deinit();
#ifdef WITH_MICROHTTPD
	_http_server_stop();
#endif
}

static char *_insert_ports(const char *src)
{
	if (!src || (!strstr(src, "{{port}}") && !strstr(src, "{{sslport}}")
	    && !strstr(src, "{{ftpport}}") && !strstr(src, "{{ftpsport}}")))
		return NULL;

	char *ret = wget_malloc(strlen(src) + 1);
	char *dst = ret;

	while (*src) {
		if (*src == '{') {
			if (!strncmp(src, "{{port}}", 8)) {
				dst += sprintf(dst, "%d", http_server_port);
				src += 8;
				continue;
			}
			else if (!strncmp(src, "{{sslport}}", 11)) {
				dst += sprintf(dst, "%d", https_server_port);
				src += 11;
				continue;
			}
			else if (!strncmp(src, "{{ftpport}}", 11)) {
				dst += sprintf(dst, "%d", ftp_server_port);
				src += 11;
				continue;
			}
			else if (!strncmp(src, "{{ftpsport}}", 12)) {
				dst += sprintf(dst, "%d", ftps_server_port);
				src += 12;
				continue;
			}
		}
		*dst++ = *src++;
	}
	*dst = 0;

	return ret;
}

static void _write_msg(const char *msg, size_t len)
{
#ifdef _WIN32
	fwrite(msg, 1, len, stderr);
#else
	if (isatty(fileno(stderr))) {
		if (len && msg[len - 1] == '\n')
			len--;

		fprintf(stderr, "\033[33m%.*s\033[m\n", (int) len, msg);
	} else
		fwrite(msg, 1, len, stderr);
#endif
}

void wget_test_start_server(int first_key, ...)
{
	static wget_tcp_t *https_parent_tcp, *ftp_parent_tcp, *ftps_parent_tcp;
	int rc, key;
	size_t it;
	va_list args;

	/* Skip any test that use this function if threads are not present.  */
	if (!wget_thread_support()) {
		wget_error_printf("THREADS NOT SUPPORTED: Skip\n");
		exit(77);
	}

	wget_global_init(
		WGET_DEBUG_FUNC, _write_msg,
		WGET_ERROR_FUNC, _write_msg,
		WGET_INFO_FUNC, _write_msg,
		NULL);

	va_start(args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
/*		case WGET_TEST_RESPONSE_BODY:
			response_body = va_arg(args, const char *);
			break;
		case WGET_TEST_RESPONSE_HEADER:
			if (!response_headers)
				response_headers = wget_vector_create(4,4,NULL);
			wget_vector_add_str(response_headers, va_arg(args, const char *));
			break;
		case WGET_TEST_RESPONSE_CODE:
			response_code = va_arg(args, const char *);
			break;
*/		case WGET_TEST_EXPECTED_REQUEST_HEADER:
			break;
		case WGET_TEST_RESPONSE_URLS:
			urls = va_arg(args, wget_test_url_t *);
			nurls = va_arg(args, size_t);
			break;
		case WGET_TEST_FTP_SERVER_HELLO:
			server_hello = va_arg(args, const char *);
			break;
		case WGET_TEST_FTP_IO_ORDERED:
			ios_ordered = 1;
			ios = va_arg(args, wget_test_ftp_io_t *);
			nios = va_arg(args, size_t);
			break;
		case WGET_TEST_FTP_IO_UNORDERED:
			ios_ordered = 0;
			ios = va_arg(args, wget_test_ftp_io_t *);
			nios = va_arg(args, size_t);
			break;
		case WGET_TEST_FTPS_IMPLICIT:
			ftps_implicit = va_arg(args, int);
			break;
		case WGET_TEST_SERVER_SEND_CONTENT_LENGTH:
			server_send_content_length = !!va_arg(args, int);
			break;
		default:
			wget_error_printf(_("Unknown option %d\n"), key);
		}
	}
	va_end(args);

	atexit(wget_test_stop_server);

	snprintf(tmpdir, sizeof(tmpdir), ".test_%d", (int) getpid());

	// remove tmpdir if exists from previous tests
	_remove_directory(tmpdir);

	if (mkdir(tmpdir, 0755) != 0)
		wget_error_printf_exit(_("Failed to create tmpdir (%d)\n"), errno);

	if (chdir(tmpdir) != 0)
		wget_error_printf_exit(_("Failed to change to tmpdir (%d)\n"), errno);

	// init server SSL layer (default cert and key file types are PEM)
	wget_ssl_set_config_string(WGET_SSL_CA_FILE, SRCDIR "/certs/x509-ca-cert.pem");
	wget_ssl_set_config_string(WGET_SSL_CERT_FILE, SRCDIR "/certs/x509-server-cert.pem");
	wget_ssl_set_config_string(WGET_SSL_KEY_FILE, SRCDIR "/certs/x509-server-key.pem");

	// init HTTPS server socket
	https_parent_tcp = wget_tcp_init();
	wget_tcp_set_ssl(https_parent_tcp, 1); // switch SSL on
	wget_tcp_set_timeout(https_parent_tcp, -1); // INFINITE timeout
	wget_tcp_set_preferred_family(https_parent_tcp, WGET_NET_FAMILY_IPV4); // to have a defined order of IPs
	if (wget_tcp_listen(https_parent_tcp, "localhost", 0, 5) != 0)
		exit(1);
	https_server_port = wget_tcp_get_local_port(https_parent_tcp);

	// init FTP server socket
	ftp_parent_tcp = wget_tcp_init();
	wget_tcp_set_timeout(ftp_parent_tcp, -1); // INFINITE timeout
	wget_tcp_set_preferred_family(ftp_parent_tcp, WGET_NET_FAMILY_IPV4); // to have a defined order of IPs
	if (wget_tcp_listen(ftp_parent_tcp, "localhost", 0, 5) != 0)
		exit(1);
	ftp_server_port = wget_tcp_get_local_port(ftp_parent_tcp);

	if (ftps_implicit) {
		// init FTPS server socket
		ftps_parent_tcp = wget_tcp_init();
		wget_tcp_set_ssl(ftps_parent_tcp, 1); // switch SSL on
		wget_tcp_set_timeout(ftps_parent_tcp, -1); // INFINITE timeout
		wget_tcp_set_preferred_family(ftps_parent_tcp, WGET_NET_FAMILY_IPV4); // to have a defined order of IPs
		if (wget_tcp_listen(ftps_parent_tcp, "localhost", 0, 5) != 0)
			exit(1);
		ftps_server_port = wget_tcp_get_local_port(ftps_parent_tcp);
	}

#ifdef WITH_MICROHTTPD
	// start HTTP server
	if ((rc = _http_server_start()) != 0)
		wget_error_printf_exit(_("Failed to start HTTP server, error %d\n"), rc);
#endif

	// now replace {{port}} in the body by the actual server port
	for (wget_test_url_t *url = urls; url < urls + nurls; url++) {
		char *p = _insert_ports(url->body);

		if (p) {
			url->body = p;
			url->body_alloc = 1;
		}

		for (it = 0; it < countof(url->headers) && url->headers[it]; it++) {
			p = _insert_ports(url->headers[it]);

			if (p) {
				url->headers[it] = p;
				url->header_alloc[it] = 1;
			}
		}
	}

	// start thread for HTTPS
	if ((rc = wget_thread_start(&https_server_tid, _http_server_thread, https_parent_tcp, 0)) != 0)
		wget_error_printf_exit(_("Failed to start HTTPS server, error %d\n"), rc);

	// start thread for FTP
	if ((rc = wget_thread_start(&ftp_server_tid, _ftp_server_thread, ftp_parent_tcp, 0)) != 0)
		wget_error_printf_exit(_("Failed to start FTP server, error %d\n"), rc);

	// start thread for FTPS
	if (ftps_implicit) {
		if ((rc = wget_thread_start(&ftps_server_tid, _ftp_server_thread, ftps_parent_tcp, 0)) != 0)
			wget_error_printf_exit(_("Failed to start FTP server, error %d\n"), rc);
	}
}

static void _scan_for_unexpected(const char *dirname, const wget_test_file_t *expected_files)
{
	DIR *dir;
	struct dirent *dp;
	struct stat st;
	size_t it, dirlen = strlen(dirname);

	wget_info_printf("Entering %s\n", dirname);

	if ((dir = opendir(dirname))) {
		while ((dp = readdir(dir))) {
			char fname[dirlen + 1 + strlen(dp->d_name) + 1];

			if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
				continue;

			if (*dirname == '.' && dirname[1] == 0)
				sprintf(fname, "%s", dp->d_name);
			else
				sprintf(fname, "%s/%s", dirname, dp->d_name);

			wget_info_printf(" - %s/%s\n", dirname, dp->d_name);
			if (stat(fname, &st) == 0 && S_ISDIR(st.st_mode)) {
				_scan_for_unexpected(fname, expected_files);
				continue;
			}

			if (expected_files) {
// Mac OS X converts to NFD, so we might find an unexpected file name, e.g. when using accents.
// Example: cedilla (%C3%A7) will be converted to c+composed_cedilla (%63%CC%A7)
// Since there are a few pitfalls with Apple's NFD, just skip the check here.
#if !(defined __APPLE__ && defined __MACH__)
				wget_info_printf("search %s\n", fname);

				for (it = 0; expected_files[it].name; it++) {
#ifdef _WIN32
					char buf[strlen(expected_files[it].name) * 3 + 1];
					const char *restricted_fname = wget_restrict_file_name(expected_files[it].name, buf,
						expected_files[it].restricted_mode ? expected_files[it].restricted_mode : WGET_RESTRICT_NAMES_WINDOWS);
#else
					const char *restricted_fname = expected_files[it].name;
#endif
/*
					{
						char b[256];
						if (it==0) {
							wget_memtohex(fname, strlen(fname), b, sizeof(b));
							wget_error_printf("f %s\n", b);
						}
						wget_memtohex(restricted_fname, strlen(restricted_fname), b, sizeof(b));
						wget_error_printf("r %s\n", b);
					}
*/
					if (!strcmp(restricted_fname, fname))
						break;
				}

				if (!expected_files[it].name)
					wget_error_printf_exit(_("Unexpected file %s/%s found\n"), tmpdir, fname);
#endif
			} else
				wget_error_printf_exit(_("Unexpected file %s/%s found\n"), tmpdir, fname);
		}

		closedir(dir);
	} else
		wget_error_printf_exit(_("Failed to diropen %s\n"), dirname);
}

void wget_test(int first_key, ...)
{
	const char
		*request_url,
		*options="",
		*executable="../../src/wget2_noinstall" EXEEXT " -d --no-config --max-threads=1 --prefer-family=ipv4 --no-proxy";
	const wget_test_file_t
		*expected_files = NULL,
		*existing_files = NULL;
	wget_buffer_t
		*cmd = wget_buffer_alloc(1024);
	unsigned
		it;
	int
		key,
		fd,
		rc,
		expected_error_code = 0;
	va_list
		args;
	char
		server_send_content_length_old = server_send_content_length;

	keep_tmpfiles = 0;
	server_hello = "220 FTP server ready";

	if (!request_urls)
		request_urls = wget_vector_create(8,8,NULL);

	va_start (args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case WGET_TEST_REQUEST_URL:
			if ((request_url = va_arg(args, const char *)))
				wget_vector_add_str(request_urls, request_url);
			break;
		case WGET_TEST_REQUEST_URLS:
			while ((request_url = va_arg(args, const char *)))
				wget_vector_add_str(request_urls, request_url);
			break;
		case WGET_TEST_EXPECTED_ERROR_CODE:
			expected_error_code = va_arg(args, int);
			break;
		case WGET_TEST_EXPECTED_FILES:
			expected_files = va_arg(args, const wget_test_file_t *);
			break;
		case WGET_TEST_EXISTING_FILES:
			existing_files = va_arg(args, const wget_test_file_t *);
			break;
		case WGET_TEST_OPTIONS:
			options = va_arg(args, const char *);
			break;
		case WGET_TEST_KEEP_TMPFILES:
			keep_tmpfiles = va_arg(args, int);
			break;
		case WGET_TEST_EXECUTABLE:
			executable = va_arg(args, const char *);
			break;
		case WGET_TEST_FTP_SERVER_HELLO:
			server_hello = va_arg(args, const char *);
			break;
		case WGET_TEST_SERVER_SEND_CONTENT_LENGTH:
			server_send_content_length = !!va_arg(args, int);
			break;
		default:
			wget_error_printf_exit(_("Unknown option %d [%s]\n"), key, options);
		}
	}
	va_end(args);

	// clean directory
	wget_buffer_printf(cmd, "../%s", tmpdir);
	_empty_directory(cmd->data);

	// create files
	if (existing_files) {
		for (it = 0; existing_files[it].name; it++) {
			if ((fd = open(existing_files[it].name, O_CREAT|O_WRONLY|O_TRUNC|O_BINARY, 0644)) != -1) {
				ssize_t nbytes = write(fd, existing_files[it].content, strlen(existing_files[it].content));
				close(fd);

				if (nbytes != (ssize_t)strlen(existing_files[it].content))
					wget_error_printf_exit(_("Failed to write %zu bytes to file %s/%s [%s]\n"),
						strlen(existing_files[it].content), tmpdir, existing_files[it].name, options);

				if (existing_files[it].timestamp) {
					// take the old utime() instead of utimes()
					if (utime(existing_files[it].name, &(struct utimbuf){ 0, existing_files[it].timestamp }))
						wget_error_printf_exit(_("Failed to set mtime of %s/%s [%s]\n"),
							tmpdir, existing_files[it].name, options);
				}

			} else {
				wget_error_printf_exit(_("Failed to write open file %s/%s [%s] (%d,%s)\n"),
					tmpdir, *existing_files[it].name == '/' ? existing_files[it].name + 1 : existing_files[it].name , options,
					errno, strerror(errno));
			}
		}
	}

	const char *valgrind = getenv("VALGRIND_TESTS");
	if (!valgrind || !*valgrind || !strcmp(valgrind, "0")) {
		// On some system we get random IP order (v4, v6) for localhost, so we need --prefer-family for testing since
		// the test servers will listen only on the first IP and also prefers IPv4
		const char *emulator = getenv("EMULATOR");
		if (emulator && *emulator)
			wget_buffer_printf(cmd, "%s %s %s", emulator, executable, options);
		else
			wget_buffer_printf(cmd, "%s %s", executable, options);
	} else if (!strcmp(valgrind, "1")) {
		wget_buffer_printf(cmd, "valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes --suppressions=" SRCDIR "/valgrind-suppressions %s %s", executable, options);
	} else
		wget_buffer_printf(cmd, "%s %s %s", valgrind, executable, options);

	for (it = 0; it < (size_t)wget_vector_size(request_urls); it++) {
		wget_buffer_printf_append(cmd, " \"http://localhost:%d/%s\"",
			http_server_port, (char *)wget_vector_get(request_urls, it));
	}
//	for (it = 0; it < (size_t)wget_vector_size(ftp_files); it++) {
//		wget_buffer_printf_append2(cmd, " 'ftp://localhost:%d/%s'",
//			ftp_server_port, (char *)wget_vector_get(ftp_files, it));
//	}
	wget_buffer_strcat(cmd, " 2>&1");

	wget_info_printf("cmd=%s\n", cmd->data);
	wget_error_printf("\n  Testing '%s'\n", cmd->data);

	// catch stdout and write to stderr so all output is in sync
	FILE *pp;
	if ((pp = popen(cmd->data, "r"))) {
		char buf[4096];

		while (fgets(buf, sizeof(buf), pp))
			fputs(buf, stderr);

		rc = pclose(pp);
	} else
		wget_error_printf_exit(_("Failed to execute test (%d) [%s]\n"), errno, options);
/*
	rc = system(cmd->data);
*/
	if (!WIFEXITED(rc)) {
		wget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"), rc, expected_error_code, options);
	}
	else if (WEXITSTATUS(rc) != expected_error_code) {
		wget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"),
			WEXITSTATUS(rc), expected_error_code, options);
	}

	if (expected_files) {
		for (it = 0; expected_files[it].name; it++) {
			struct stat st;
#ifdef _WIN32
			char buf[strlen(expected_files[it].name) * 3 + 1];
			const char *fname = wget_restrict_file_name(expected_files[it].name, buf,
				expected_files[it].restricted_mode ? expected_files[it].restricted_mode : WGET_RESTRICT_NAMES_WINDOWS);
#else
			const char *fname = expected_files[it].name;
#endif

			if (stat(fname, &st) != 0)
				wget_error_printf_exit(_("Missing expected file '%s/%s' [%s]\n"), tmpdir, fname, options);

			if (expected_files[it].content) {
				char *content = wget_malloc(st.st_size ? st.st_size : 1);

				if ((fd = open(fname, O_RDONLY | O_BINARY)) != -1) {
					ssize_t nbytes = read(fd, content, st.st_size);
					close(fd);

					if (nbytes != st.st_size)
						wget_error_printf_exit(_("Failed to read %lld bytes from file '%s/%s', just got %zd [%s]\n"),
							(long long)st.st_size, tmpdir, fname, nbytes, options);

					if (strlen(expected_files[it].content) != (size_t)nbytes || memcmp(expected_files[it].content, content, nbytes) != 0)
						wget_error_printf_exit(_("Unexpected content in %s [%s]\n"), fname, options);
				}

				wget_free(content);
			}

			if (expected_files[it].timestamp && st.st_mtime != expected_files[it].timestamp)
				wget_error_printf_exit(_("Unexpected timestamp '%s/%s' [%s]\n"), tmpdir, fname, options);
		}
	}

	// look if there are unexpected files in our working dir
	_scan_for_unexpected(".", expected_files);

	wget_vector_clear(request_urls);
	wget_buffer_free(&cmd);

	server_send_content_length = server_send_content_length_old;

	// system("ls -la");
}

int wget_test_get_http_server_port(void)
{
	return http_server_port;
}

int wget_test_get_https_server_port(void)
{
	return https_server_port;
}

int wget_test_get_ftp_server_port(void)
{
	return ftp_server_port;
}

int wget_test_get_ftps_server_port(void)
{
	return ftps_server_port;
}

// assume that we are in 'tmpdir'
int wget_test_check_file_system(void)
{
	static char fname[3][3] = { "Ab", "ab", "AB" };
	char buf[sizeof(fname[0])];
	int flags = 0, fd;
	ssize_t rc;

	_empty_directory(tmpdir);

	// Create 3 files with differently cased names with different content.
	// On a case-mangling file system like HFS+ there will be just one file with the contents of the last write.
	for (unsigned it = 0; it < countof(fname); it++) {
		if ((fd = open(fname[it], O_WRONLY | O_TRUNC | O_CREAT | O_BINARY, 0644)) != -1) {
			rc = write(fd, fname[it], sizeof(fname[0]));
			close(fd);

			if (rc != sizeof(fname[0])) {
				wget_debug_printf("%s: Failed to write to '%s/%s' (%d) %zd %zu\n", __func__, tmpdir, fname[it], errno, rc, sizeof(fname[0]));
				goto out;
			}
		} else {
			wget_debug_printf("%s: Failed to write open '%s/%s'\n", __func__, tmpdir, fname[it]);
			goto out;
		}
	}

	// Check file content to see if FS is case-mangling
	for (unsigned it = 0; it < countof(fname); it++) {
		if ((fd = open(fname[it], O_RDONLY | O_BINARY, 0644)) != -1) {
			rc = read(fd, buf, sizeof(fname[0]));
			close(fd);

			if (rc != sizeof(fname[0])) {
				wget_debug_printf("%s: Failed to read from '%s/%s'\n", __func__, tmpdir, fname[it]);
				goto out;
			}

			if (strcmp(buf, fname[it])) {
				wget_debug_printf("%s: Found case-mangling file system\n", __func__);
				flags = WGET_TEST_FS_CASEMATTERS;
				goto out; // we can stop here
			}
		} else {
			wget_debug_printf("%s: Failed to read open '%s/%s'\n", __func__, tmpdir, fname[it]);
			goto out;
		}
	}

	wget_debug_printf("%s: Found case-respecting file system\n", __func__);

out:
	_empty_directory(tmpdir);

	return flags;
}

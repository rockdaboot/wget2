/*
 * Copyright(c) 2013-2014 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <utime.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <libmget.h>

#include "libtest.h"

static mget_thread_t
	http_server_tid,
	https_server_tid,
	ftp_server_tid,
	ftps_server_tid;
static int
	http_server_port,
	https_server_port,
	ftp_server_port,
	ftps_server_port,
	ftps_implicit,
	terminate,
	keep_tmpfiles;
/*static const char
	*response_code = "200 Dontcare",
	*response_body = "";
static MGET_VECTOR
	*response_headers; */
static mget_vector_t
	*request_urls;
static mget_test_url_t
	*urls;
static size_t
	nurls;
static mget_test_ftp_io_t
	*ios;
static size_t
	nios;
static int
	ios_ordered;
static char
	tmpdir[128];
static const char
	*server_hello;

static void sigterm_handler(int sig G_GNUC_MGET_UNUSED)
{
	terminate = 1;
}

static void *_http_server_thread(void *ctx)
{
	mget_tcp_t *tcp=NULL, *parent_tcp = ctx;
	mget_test_url_t *url = NULL;
	char buf[4096], method[32], request_url[256], tag[64], value[256], *p;
	ssize_t nbytes, from_bytes, to_bytes;
	size_t body_len, request_url_length;
	unsigned it;
	int byterange, authorized;
	time_t modified;

#if defined(_WIN32) || defined(_WIN64)
	signal(SIGTERM, sigterm_handler);
#else
	sigaction(SIGTERM, &(struct sigaction) { .sa_handler = sigterm_handler }, NULL);
#endif

	while (!terminate) {
		mget_tcp_deinit(&tcp);

		if ((tcp = mget_tcp_accept(parent_tcp))) {
			authorized = 0;

			// as a quick hack, just assume that request comes in one packet
			if ((nbytes = mget_tcp_read(tcp, buf, sizeof(buf)-1)) > 0) {
				buf[nbytes]=0;
				if (sscanf(buf, "%31s %255s", method, request_url) !=2) {
					mget_tcp_printf(tcp, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
					continue;
				}

				byterange = from_bytes = to_bytes = 0;
				modified = 0;

				for (p = strstr(buf, "\r\n"); sscanf(p, "\r\n%63[^:]: %255[^\r]", tag, value) == 2; p = strstr(p + 2, "\r\n")) {
					if (!mget_strcasecmp_ascii(tag, "Range")) {
						if ((byterange = sscanf(value, "bytes=%zd-%zd", &from_bytes, &to_bytes)) < 1)
							byterange = 0;
					}
					else if (url && !mget_strcasecmp_ascii(tag, "Authorization")) {
						const char *auth_scheme, *s;

						s=mget_http_parse_token(value, &auth_scheme);
						while (isblank(*s)) s++;

						if (!mget_strcasecmp_ascii(auth_scheme, "basic")) {
							const char *encoded = mget_base64_encode_printf_alloc("%s:%s", url->auth_username, url->auth_password);

							mget_error_printf("Auth check '%s' <-> '%s'\n", encoded, s);
							if (!strcmp(encoded, s))
								authorized = 1;

							mget_xfree(encoded);
						}

						mget_xfree(auth_scheme);
					}
					else if (!mget_strcasecmp_ascii(tag, "If-Modified-Since")) {
						modified = mget_http_parse_full_date(value);
						mget_info_printf("modified = %ld\n", modified);
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
					mget_tcp_printf(tcp, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
					continue;
				}

				if (url->auth_method && !authorized) {
					if (!mget_strcasecmp_ascii(url->auth_method, "basic"))
						mget_tcp_printf(tcp,
							"HTTP/1.1 401 Unauthorized\r\n" \
							"WWW-Authenticate: %s realm=\"Protected Page\"\r\n" \
							"Connection: close\r\n\r\n",
							url->auth_method);
					else
						mget_error_printf(_("Unknown authentication scheme '%s'\n"), url->auth_method);

					continue;
				}

				if (modified && url->modified<=modified) {
					mget_tcp_printf(tcp,"HTTP/1.1 304 Not Modified\r\n\r\n");
					continue;
				}

				if (byterange == 1) {
					to_bytes = strlen(url->body) - 1;
				}
				if (byterange) {
					if (from_bytes > to_bytes || from_bytes >= (int)strlen(url->body)) {
						mget_tcp_printf(tcp, "HTTP/1.1 416 Range Not Satisfiable\r\nConnection: close\r\n\r\n");
						continue;
					}

					// create response
					body_len = to_bytes - from_bytes + 1;
					nbytes = snprintf(buf, sizeof(buf),
						"HTTP/1.1 206 Partial Content\r\n"\
						"Content-Length: %zu\r\n"\
						"Accept-Ranges: bytes\r\n"\
						"Content-Range: %zd-%zd/%zu\r\n",
						body_len, from_bytes, to_bytes, body_len);
					for (it = 0; it < countof(url->headers) && url->headers[it]; it++) {
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s\r\n", url->headers[it]);
					}
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "\r\n");
					if (!strcmp(method, "GET") || !strcmp(method, "POST"))
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%.*s", (int)body_len, url->body + from_bytes);
				} else {
					// create response
					body_len = strlen(url->body ? url->body : "");
					nbytes = snprintf(buf, sizeof(buf),
						"HTTP/1.1 %s\r\n"\
						"Content-Length: %zu\r\n",
						url->code ? url->code : "200 OK\r\n", body_len);
					for (it = 0; it < countof(url->headers) && url->headers[it]; it++) {
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s\r\n", url->headers[it]);
					}
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "\r\n");
					if (!strcmp(method, "GET") || !strcmp(method, "POST"))
						nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s", url->body ? url->body : "");
				}

				// send response
				mget_tcp_write(tcp, buf, nbytes);
			}
		} else if (!terminate)
			mget_error_printf(_("Failed to get connection (%d)\n"), errno);
	}

	mget_tcp_deinit(&parent_tcp);

	return NULL;
}

static void *_ftp_server_thread(void *ctx)
{
	mget_tcp_t *tcp = NULL, *parent_tcp = ctx, *pasv_parent_tcp = NULL, *pasv_tcp = NULL;
	char buf[4096];
	ssize_t nbytes;
	int pasv_port, found;
	unsigned io_pos;

#if defined(_WIN32) || defined(_WIN64)
	signal(SIGTERM, sigterm_handler);
#else
	sigaction(SIGTERM, &(struct sigaction) { .sa_handler = sigterm_handler }, NULL);
#endif

	while (!terminate) {
		mget_tcp_deinit(&tcp);
		mget_tcp_deinit(&pasv_tcp);
		mget_tcp_deinit(&pasv_parent_tcp);

		if ((tcp = mget_tcp_accept(parent_tcp))) {
			io_pos = 0;

			if (server_hello)
				mget_tcp_printf(tcp, "%s\r\n", server_hello);

			// as a quick hack, just assume that each line comes in one packet
			while ((nbytes = mget_tcp_read(tcp, buf, sizeof(buf)-1)) > 0) {
				buf[nbytes] = 0;

				while (--nbytes >= 0 && (buf[nbytes] == '\r' || buf[nbytes] == '\n'))
					buf[nbytes] = 0;

				mget_debug_printf("### Got: '%s'\n", buf);

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
					mget_error_printf(_("Unexpected input: '%s'\n"), buf);
					mget_tcp_printf(tcp, "500 Unknown command\r\n");
					continue;
				}

				if (!strncmp(buf, "AUTH", 4)) {
					// assume TLS auth type
					mget_tcp_printf(tcp, "%s\r\n", ios[io_pos].out);
					if (atoi(ios[io_pos].out)/100 == 2)
						mget_tcp_tls_start(tcp);
					io_pos++;
					continue;
				}

				if (!strncmp(buf, "PASV", 4) || !strncmp(buf, "EPSV", 4)) {
					// init FTP PASV/EPSV socket
					// we ignore EPSV address type here, we listen on IPv4 and IPv6 anyways
					pasv_parent_tcp=mget_tcp_init();
					mget_tcp_set_timeout(pasv_parent_tcp, -1); // INFINITE timeout
					if (!strncmp(buf, "EPSV", 4)) {
						switch (atoi(buf+4)) {
							case 1: mget_tcp_set_family(pasv_parent_tcp, MGET_NET_FAMILY_IPV4); break;
							case 2: mget_tcp_set_family(pasv_parent_tcp, MGET_NET_FAMILY_IPV6); break;
							default: mget_tcp_set_family(pasv_parent_tcp, MGET_NET_FAMILY_ANY); break;
						}
					}
					if (mget_tcp_listen(pasv_parent_tcp, "localhost", NULL, 5) != 0) {
						mget_tcp_printf(tcp, "500 failed to open port\r\n");
						break;
					}
					pasv_port = mget_tcp_get_local_port(pasv_parent_tcp);

					const char *src = ios[io_pos].out;
					char *response = mget_malloc(strlen(src) + 32 + 1);
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

					mget_tcp_printf(tcp, "%s\r\n", response);
					mget_xfree(response);

					if (!(pasv_tcp = mget_tcp_accept(pasv_parent_tcp))) {
						mget_error_printf(_("Failed to get PASV connection\n"));
						break;
					}
				} else {
					mget_tcp_printf(tcp, "%s\r\n", ios[io_pos].out);
				}

				if (ios[io_pos].send_url && pasv_tcp) {
					// send data
					mget_tcp_printf(pasv_tcp, "%s", ios[io_pos].send_url->body);
					mget_tcp_deinit(&pasv_tcp);
					mget_tcp_printf(tcp, "226 Transfer complete\r\n");
				}

				io_pos++;
			}
		} else if (!terminate)
			mget_error_printf(_("Failed to get connection (%d)\n"), errno);
	}

	mget_tcp_deinit(&parent_tcp);

	return NULL;
}

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
				if (errno == EISDIR)
					_remove_directory(fname);
				else
					mget_error_printf(_("Failed to unlink %s (%d)\n"), fname, errno);
			}
		}

		closedir(dir);
	} else
		mget_error_printf(_("Failed to opendir %s\n"), dirname);
}

static void _remove_directory(const char *dirname)
{
	_empty_directory(dirname);
	if (rmdir(dirname) == -1)
		mget_error_printf(_("Failed to rmdir %s\n"), dirname);
}

void mget_test_stop_server(void)
{
	size_t it;

//	mget_vector_free(&response_headers);
	mget_vector_free(&request_urls);

	for (it = 0; it < nurls; it++) {
		if (urls[it].body_alloc) {
			mget_xfree(urls[it].body);
			urls[it].body_alloc = 0;
		}
	}

	if (chdir("..") != 0)
		mget_error_printf(_("Failed to chdir ..\n"));

	if (!keep_tmpfiles)
		_remove_directory(tmpdir);

	// free resources - needed for valgrind testing
	pthread_kill(http_server_tid, SIGTERM);
	pthread_kill(https_server_tid, SIGTERM);
	pthread_kill(ftp_server_tid, SIGTERM);
	if (ftps_implicit)
		pthread_kill(ftps_server_tid, SIGTERM);

	mget_thread_join(http_server_tid);
	mget_thread_join(https_server_tid);
	mget_thread_join(ftp_server_tid);
	if (ftps_implicit)
		mget_thread_join(ftps_server_tid);

	mget_global_deinit();
}

void mget_test_start_server(int first_key, ...)
{
	static mget_tcp_t *http_parent_tcp, *https_parent_tcp, *ftp_parent_tcp, *ftps_parent_tcp;
	int rc, key;
	size_t it;
	va_list args;

	mget_global_init(
		MGET_DEBUG_STREAM, stderr,
		MGET_ERROR_STREAM, stderr,
//		MGET_INFO_STREAM, stdout,
		NULL);

	va_start(args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
/*		case MGET_TEST_RESPONSE_BODY:
			response_body = va_arg(args, const char *);
			break;
		case MGET_TEST_RESPONSE_HEADER:
			if (!response_headers)
				response_headers = mget_vector_create(4,4,NULL);
			mget_vector_add_str(response_headers, va_arg(args, const char *));
			break;
		case MGET_TEST_RESPONSE_CODE:
			response_code = va_arg(args, const char *);
			break;
*/		case MGET_TEST_EXPECTED_REQUEST_HEADER:
			break;
		case MGET_TEST_RESPONSE_URLS:
			urls = va_arg(args, mget_test_url_t *);
			nurls = va_arg(args, size_t);
			break;
		case MGET_TEST_FTP_SERVER_HELLO:
			server_hello = va_arg(args, const char *);
			break;
		case MGET_TEST_FTP_IO_ORDERED:
			ios_ordered = 1;
			ios = va_arg(args, mget_test_ftp_io_t *);
			nios = va_arg(args, size_t);
			break;
		case MGET_TEST_FTP_IO_UNORDERED:
			ios_ordered = 0;
			ios = va_arg(args, mget_test_ftp_io_t *);
			nios = va_arg(args, size_t);
			break;
		case MGET_TEST_FTPS_IMPLICIT:
			ftps_implicit = va_arg(args, int);
			break;
		default:
			mget_error_printf(_("Unknown option %d\n"), key);
		}
	}
	va_end(args);

	atexit(mget_test_stop_server);

	snprintf(tmpdir, sizeof(tmpdir), ".test_%d", (int) getpid());

#if defined(_WIN32) || defined(_WIN64)
	if (mkdir(tmpdir) != 0)
#else
	if (mkdir(tmpdir, 0755) != 0)
#endif
		mget_error_printf_exit(_("Failed to create tmpdir (%d)\n"), errno);

	if (chdir(tmpdir) != 0)
		mget_error_printf_exit(_("Failed to change to tmpdir (%d)\n"), errno);

	// init server SSL layer (default cert and key file types are PEM)
	// SRCDIR is the (relative) path to the tests dir. Since we chdir()'ed into a subdirectory, we need "../"
	mget_ssl_set_config_string(MGET_SSL_CA_FILE, "../" SRCDIR "/certs/x509-ca-cert.pem");
	mget_ssl_set_config_string(MGET_SSL_CERT_FILE, "../" SRCDIR "/certs/x509-server-cert.pem");
	mget_ssl_set_config_string(MGET_SSL_KEY_FILE, "../" SRCDIR "/certs/x509-server-key.pem");

	// init HTTP server socket
	http_parent_tcp=mget_tcp_init();
	mget_tcp_set_timeout(http_parent_tcp, -1); // INFINITE timeout
	if (mget_tcp_listen(http_parent_tcp, "localhost", NULL, 5) != 0)
		exit(1);
	http_server_port = mget_tcp_get_local_port(http_parent_tcp);

	// init HTTPS server socket
	https_parent_tcp=mget_tcp_init();
	mget_tcp_set_ssl(https_parent_tcp, 1); // switch SSL on
	mget_tcp_set_timeout(https_parent_tcp, -1); // INFINITE timeout
	if (mget_tcp_listen(https_parent_tcp, "localhost", NULL, 5) != 0)
		exit(1);
	https_server_port = mget_tcp_get_local_port(https_parent_tcp);

	// init FTP server socket
	ftp_parent_tcp=mget_tcp_init();
	mget_tcp_set_timeout(ftp_parent_tcp, -1); // INFINITE timeout
	if (mget_tcp_listen(ftp_parent_tcp, "localhost", NULL, 5) != 0)
		exit(1);
	ftp_server_port = mget_tcp_get_local_port(ftp_parent_tcp);

	// init FTPS server socket
	ftps_parent_tcp=mget_tcp_init();
	mget_tcp_set_ssl(ftps_parent_tcp, 1); // switch SSL on
	mget_tcp_set_timeout(ftps_parent_tcp, -1); // INFINITE timeout
	if (mget_tcp_listen(ftps_parent_tcp, "localhost", NULL, 5) != 0)
		exit(1);
	ftps_server_port = mget_tcp_get_local_port(ftps_parent_tcp);

	// now replace {{port}} in the body by the actual server port
	for (it = 0; it < nurls; it++) {
		if (urls[it].body && (strstr(urls[it].body, "{{port}}") || strstr(urls[it].body, "{{sslport}}")
				  || strstr(urls[it].body, "{{ftpport}}") || strstr(urls[it].body, "{{ftpsport}}")))
		{
			const char *src = urls[it].body;
			char *dst = mget_malloc(strlen(src) + 1);

			urls[it].body = dst;
			urls[it].body_alloc = 1;

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
		}
	}

	// start thread for HTTP
	if ((rc = mget_thread_start(&http_server_tid, _http_server_thread, http_parent_tcp, 0)) != 0)
		mget_error_printf_exit(_("Failed to start HTTP server, error %d\n"), rc);

	// start thread for HTTPS
	if ((rc = mget_thread_start(&https_server_tid, _http_server_thread, https_parent_tcp, 0)) != 0)
		mget_error_printf_exit(_("Failed to start HTTPS server, error %d\n"), rc);

	// start thread for FTP
	if ((rc = mget_thread_start(&ftp_server_tid, _ftp_server_thread, ftp_parent_tcp, 0)) != 0)
		mget_error_printf_exit(_("Failed to start FTP server, error %d\n"), rc);

	// start thread for FTPS
	if (ftps_implicit) {
		if ((rc = mget_thread_start(&ftps_server_tid, _ftp_server_thread, ftps_parent_tcp, 0)) != 0)
			mget_error_printf_exit(_("Failed to start FTP server, error %d\n"), rc);
	}
}

static void _scan_for_unexpected(const char *dirname, const mget_test_file_t *expected_files)
{
	DIR *dir;
	struct dirent *dp;
	struct stat st;
	size_t it, dirlen = strlen(dirname);

	mget_info_printf("Entering %s\n", dirname);

	if ((dir = opendir(dirname))) {
		while ((dp = readdir(dir))) {
			char fname[dirlen + 1 + strlen(dp->d_name) + 1];

			if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
				continue;

			if (*dirname == '.' && dirname[1] == 0)
				sprintf(fname, "%s", dp->d_name);
			else
				sprintf(fname, "%s/%s", dirname, dp->d_name);

			mget_info_printf(" - %s/%s\n", dirname, dp->d_name);
			if (stat(fname, &st) == 0 && S_ISDIR(st.st_mode)) {
				_scan_for_unexpected(fname, expected_files);
				continue;
			}

			if (expected_files) {
				mget_info_printf("search %s\n", fname);

				for (it = 0; expected_files[it].name && strcmp(expected_files[it].name, fname); it++);

				if (!expected_files[it].name)
					mget_error_printf_exit(_("Unexpected file %s/%s found\n"), tmpdir, fname);
			} else
				mget_error_printf_exit(_("Unexpected file %s/%s found\n"), tmpdir, fname);
		}

		closedir(dir);
	} else
		mget_error_printf_exit(_("Failed to diropen %s\n"), dirname);
}

void mget_test(int first_key, ...)
{
	const char
		*request_url,
		*options="",
		*executable="../../src/mget";
	const mget_test_file_t
		*expected_files = NULL,
		*existing_files = NULL;
	mget_buffer_t
		*cmd = mget_buffer_alloc(1024);
	unsigned
		it;
	int
		key,
		fd,
		rc,
		expected_error_code = 0;
	va_list args;

	keep_tmpfiles = 0;
	server_hello = "220 FTP server ready";

	if (!request_urls)
		request_urls = mget_vector_create(8,8,NULL);

	va_start (args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case MGET_TEST_REQUEST_URL:
			if ((request_url = va_arg(args, const char *)))
				mget_vector_add_str(request_urls, request_url);
			break;
		case MGET_TEST_REQUEST_URLS:
			while ((request_url = va_arg(args, const char *)))
				mget_vector_add_str(request_urls, request_url);
			break;
		case MGET_TEST_EXPECTED_ERROR_CODE:
			expected_error_code = va_arg(args, int);
			break;
		case MGET_TEST_EXPECTED_FILES:
			expected_files = va_arg(args, const mget_test_file_t *);
			break;
		case MGET_TEST_EXISTING_FILES:
			existing_files = va_arg(args, const mget_test_file_t *);
			break;
		case MGET_TEST_OPTIONS:
			options = va_arg(args, const char *);
			break;
		case MGET_TEST_KEEP_TMPFILES:
			keep_tmpfiles = va_arg(args, int);
			break;
		case MGET_TEST_EXECUTABLE:
			executable = va_arg(args, const char *);
			break;
		case MGET_TEST_FTP_SERVER_HELLO:
			server_hello = va_arg(args, const char *);
			break;
		default:
			mget_error_printf_exit(_("Unknown option %d [%s]\n"), key, options);
		}
	}

	// clean directory
	mget_buffer_printf2(cmd, "../%s", tmpdir);
	_empty_directory(cmd->data);

	// create files
	if (existing_files) {
		for (it = 0; existing_files[it].name; it++) {
			if ((fd = open(existing_files[it].name, O_CREAT|O_WRONLY|O_TRUNC, 0644)) != -1) {
				ssize_t nbytes = write(fd, existing_files[it].content, strlen(existing_files[it].content));
				close(fd);

				if (nbytes != (ssize_t)strlen(existing_files[it].content))
					mget_error_printf_exit(_("Failed to write %zu bytes to file %s/%s [%s]\n"),
						strlen(existing_files[it].content), tmpdir, existing_files[it].name, options);

				if (existing_files[it].timestamp) {
					// take the old utime() instead of utimes()
					if (utime(existing_files[it].name, &(struct utimbuf){ 0, existing_files[it].timestamp }))
						mget_error_printf_exit(_("Failed to set mtime of %s/%s [%s]\n"),
							tmpdir, existing_files[it].name, options);
				}

			} else {
				mget_error_printf_exit(_("Failed to write open file %s/%s [%s] (%d,%s)\n"),
					tmpdir, *existing_files[it].name == '/' ? existing_files[it].name + 1 : existing_files[it].name , options,
					errno, strerror(errno));
			}
		}
	}

	const char *valgrind = getenv("VALGRIND_TESTS");
	if (!valgrind || !*valgrind || !strcmp(valgrind, "0")) {
		mget_buffer_printf2(cmd, "%s %s", executable, options);
	} else if (!strcmp(valgrind, "1")) {
		mget_buffer_printf2(cmd, "valgrind --error-exitcode=301 --leak-check=yes --show-reachable=yes --track-origins=yes %s %s", executable, options);
	} else
		mget_buffer_printf2(cmd, "%s %s %s", valgrind, executable, options);

	for (it = 0; it < (size_t)mget_vector_size(request_urls); it++) {
		mget_buffer_printf_append2(cmd, " 'http://localhost:%d/%s'",
			http_server_port, (char *)mget_vector_get(request_urls, it));
	}
//	for (it = 0; it < (size_t)mget_vector_size(ftp_files); it++) {
//		mget_buffer_printf_append2(cmd, " 'ftp://localhost:%d/%s'",
//			ftp_server_port, (char *)mget_vector_get(ftp_files, it));
//	}
	mget_buffer_strcat(cmd, " 2>&1");

	mget_error_printf("\n  Testing '%s'\n", cmd->data);
	rc = system(cmd->data);

#if defined(_WIN32) || defined(_WIN64)
	if (rc) {
		mget_error_printf_exit(_("Failed to execute command (%d)\n"), errno);
	}/* else {
		if ((fp = fopen("exit_code", "r"))) {
			if (fscanf(fp, "%d", &rc) != 1)
				mget_error_printf_exit(_("Failed to fetch exit code\n"));
			else if (rc != expected_error_code) {
				mget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"),
					rc, expected_error_code, options);
			fclose(fp);
		} else
			mget_error_printf_exit(_("Failed to execute command (%d)\n"), errno);
	}
	unlink("exit_code"); */
#else
	if (!WIFEXITED(rc)) {
		mget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"), rc, expected_error_code, options);
	}
	else if (WEXITSTATUS(rc) != expected_error_code) {
		mget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"),
			WEXITSTATUS(rc), expected_error_code, options);
	}
#endif

	if (expected_files) {
		for (it = 0; expected_files[it].name; it++) {
			struct stat st;

			if (stat(expected_files[it].name, &st) != 0)
				mget_error_printf_exit(_("Missing expected file %s/%s [%s]\n"), tmpdir, expected_files[it].name, options);

			if (expected_files[it].content) {
				char content[st.st_size];

				if ((fd = open(expected_files[it].name, O_RDONLY)) != -1) {
					ssize_t nbytes = read(fd, content, st.st_size);
					close(fd);

					if (nbytes != st.st_size)
						mget_error_printf_exit(_("Failed to read %lld bytes from file %s/%s [%s]\n"),
							(long long)st.st_size, tmpdir, expected_files[it].name, options);

					if (strlen(expected_files[it].content) != (size_t)nbytes || memcmp(expected_files[it].content, content, nbytes) != 0)
						mget_error_printf_exit(_("Unexpected content in %s [%s]\n"), expected_files[it].name, options);
				}
			}

			if (expected_files[it].timestamp && st.st_mtime != expected_files[it].timestamp)
				mget_error_printf_exit(_("Unexpected timestamp %s/%s [%s]\n"), tmpdir, expected_files[it].name, options);
		}
	}

	// look if there are unexpected files in our working dir
	_scan_for_unexpected(".", expected_files);

	mget_vector_clear(request_urls);
	mget_buffer_free(&cmd);

	//	system("ls -la");
}

int mget_test_get_http_server_port(void)
{
	return http_server_port;
}

int mget_test_get_https_server_port(void)
{
	return https_server_port;
}

int mget_test_get_ftp_server_port(void)
{
	return ftp_server_port;
}

int mget_test_get_ftps_server_port(void)
{
	return ftps_server_port;
}

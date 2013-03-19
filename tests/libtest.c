/*
 * Copyright(c) 2013 Tim Ruehsen
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
 * Example for retrieving and parsing an HTTP URI
 *
 * Changelog
 * 16.01.2013  Tim Ruehsen  created
 *
 * Simple demonstration how to download an URL with high level API functions.
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
#include <sys/stat.h>
#include <sys/time.h>
#include <libmget.h>

#include "libtest.h"

static mget_thread_t
	server_tid;
static MGET_TCP
	*parent_tcp;
static int
	server_port;
/*static const char
	*response_code = "200 Dontcare",
	*response_body = "";
static MGET_VECTOR
	*response_headers; */
static mget_test_url_t
	*urls;
static size_t
	nurls;
static char
	tmpdir[128];

static void *_server_thread(void *ctx G_GNUC_MGET_UNUSED)
{
	MGET_TCP *tcp=NULL;
	mget_test_url_t *url;
	char buf[4096], method[32], request_url[256];
	ssize_t nbytes;
	size_t body_len, request_url_length;
	unsigned it;

	while (server_tid) {
		mget_tcp_deinit(&tcp);

		if ((tcp = mget_tcp_accept(parent_tcp))) {
			// as a quick hack, just assume that request comes in one packet
			if ((nbytes = mget_tcp_read(tcp, buf, sizeof(buf)-1)) > 0) {
				buf[nbytes]=0;
				if (sscanf(buf, "%31s %255s", method, request_url) !=2 || *request_url != '/') {
					mget_tcp_printf(tcp, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
					continue;
				}

				url = NULL;
				request_url_length = strlen(request_url);

				if (request_url[request_url_length - 1] == '/') {
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
					for (it = 0; it < nurls; it++) {
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

				// send response
				body_len = strlen(url->body ? url->body : "");
				nbytes = snprintf(buf, sizeof(buf),
					"HTTP/1.1 %s\r\n"\
					"Content-Length: %zu\r\n",
					url->code, body_len);
				for (it = 0; it < countof(url->headers) && url->headers[it]; it++) {
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s\r\n", url->headers[it]);
				}
				nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "\r\n");
				if (!strcmp(method, "GET"))
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s", url->body ? url->body : "");

				mget_tcp_write(tcp, buf, nbytes);
			}
		} else
			mget_info_printf(_("Failed to get connection\n"));
	}

	return NULL;
}

void mget_test_stop_http_server(void)
{
	char cmd[128];
	size_t it;

//	mget_vector_free(&response_headers);

	for (it = 0; it < nurls; it++) {
		if (urls[it].body_alloc) {
			mget_xfree(urls[it].body);
			urls[it].body_alloc = 0;
		}
	}

	if (chdir("..") != 0)
		mget_error_printf(_("Failed to chdir ..\n"));

	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
	if (system(cmd) != 0)
		mget_error_printf(_("Failed to remove tmpdir %s\n"), tmpdir);

	// free resources - needed for valgrind testing
//	mget_thread_t tid = server_tid;
//	server_tid = 0;
	pthread_kill(server_tid, SIGKILL);
	mget_thread_join(server_tid);
	mget_tcp_deinit(&parent_tcp);
	mget_global_deinit();
}

void mget_test_start_http_server(int first_key, ...)
{
	int rc, key;
	size_t it;
	va_list args;

	mget_global_init(
//		MGET_DEBUG_STREAM, stderr,
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
		default:
			mget_error_printf(_("Unknown option %d\n"), key);
		}
	}
	va_end(args);

	atexit(mget_test_stop_http_server);

	snprintf(tmpdir, sizeof(tmpdir), ".test_%d", getpid());

	if (mkdir(tmpdir, 0755) != 0)
			mget_error_printf_exit(_("Failed to create tmpdir (%d)\n"), errno);

	if (chdir(tmpdir) != 0)
		mget_error_printf_exit(_("Failed to change to tmpdir (%d)\n"), errno);

	parent_tcp=mget_tcp_init();

	mget_tcp_set_timeout(parent_tcp, -1); // INFINITE timeout

	if (mget_tcp_listen(parent_tcp, "localhost", NULL, 5) != 0)
		exit(1);

	server_port = mget_tcp_get_local_port(parent_tcp);

	// now replace {{port}} in the body by the actual server port
	for (it = 0; it < nurls; it++) {
		if (urls[it].body && strstr(urls[it].body, "{{port}}")) {
			const char *src = urls[it].body;
			char *dst = mget_malloc(strlen(src) + 1);

			urls[it].body = dst;
			urls[it].body_alloc = 1;

			while (*src) {
				if (*src == '{' && !strncmp(src, "{{port}}", 8)) {
					dst += sprintf(dst, "%d", server_port);
					src += 8;
				} else *dst++ = *src++;
			}
			*dst = 0;
		}
	}

	// init thread attributes
	if ((rc = mget_thread_start(&server_tid, _server_thread, NULL, 0)) != 0)
		mget_error_printf_exit(_("Failed to start server, error %d\n"), rc);
}

void mget_test(int first_key, ...)
{
	char cmd[1024];
	const char
		*request_url = "index.html",
		*options="";
	const mget_test_file_t
		*expected_files = NULL,
		*existing_files = NULL;
	size_t
		it;
	int
		fd,
		rc,
		expected_error_code = 0;

	int key;
	va_list args;

	va_start (args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case MGET_TEST_REQUEST_URL:
			request_url = va_arg(args, const char *);
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
		default:
			mget_error_printf_exit(_("Unknown option %d [%s]\n"), key, options);
		}
	}

	// clean directory
	snprintf(cmd, sizeof(cmd), "rm -rf ../%s/*", tmpdir);
	if (system(cmd) != 0)
		mget_error_printf_exit(_("Failed to wipe tmpdir %s\n"), tmpdir);

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
					if (utime(existing_files[it].name, &(struct utimbuf){ 0, existing_files[it].timestamp}))
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

	//	snprintf(cmd, sizeof(cmd), "../../src/mget -q %s http://localhost:%d/%s", options, server_port, request_url);
	snprintf(cmd, sizeof(cmd), "wget -q %s http://localhost:%d/%s", options, server_port, request_url);
	rc = system(cmd);
	if (!WIFEXITED(rc)) {
		mget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"), rc, expected_error_code, options);
	}
	else if (WEXITSTATUS(rc) != expected_error_code) {
		mget_error_printf_exit(_("Unexpected error code %d, expected %d [%s]\n"),
			WEXITSTATUS(rc), expected_error_code, options);
	}

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
						mget_error_printf_exit(_("Failed to read %zd bytes from file %s/%s [%s]\n"),
							st.st_size, tmpdir, expected_files[it].name, options);

					if (strlen(expected_files[it].content) != (size_t)nbytes || memcmp(expected_files[it].content, content, nbytes) != 0)
						mget_error_printf_exit(_("Unexpected content in %s [%s]\n"), expected_files[it].name, options);
				}
			}

			if (expected_files[it].timestamp && st.st_mtime != expected_files[it].timestamp)
				mget_error_printf_exit(_("Unexpected timestamp %s/%s [%s]\n"), tmpdir, expected_files[it].name, options);
		}
	}

//	system("ls -la");
}

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
#include <sys/stat.h>
#include <libmget.h>

#include "libtest.h"

static mget_thread_t
	server_tid;
static MGET_TCP
	*parent_tcp;
static int
	server_port;
static const char
	*response_code = "200 OK",
	*response_body = "";
static MGET_VECTOR
	*response_headers;
static char
	tmpdir[128];

static void *_server_thread(void *ctx G_GNUC_MGET_UNUSED)
{
	MGET_TCP *tcp;
	char buf[4096];
	ssize_t nbytes;
	size_t body_len;
	int it;

	while (server_tid) {
		if ((tcp = mget_tcp_accept(parent_tcp))) {
			// as a quick hack, just assume that request comes in one packet
			if ((nbytes = mget_tcp_read(tcp, buf, sizeof(buf)-1)) >= 0) {
//				buf[nbytes] = 0;
//				if ((body = strstr(buf, "\r\n\r\n"))) {
//					body += 4;
//				}

				// send response
				body_len = strlen(response_body ? response_body : "");
				nbytes = snprintf(buf, sizeof(buf),
					"HTTP/1.1 %s\r\n"\
					"Content-Length: %zu\r\n",
					response_code, body_len);
				for (it = 0; it < mget_vector_size(response_headers); it++) {
					nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s\r\n", (char *)mget_vector_get(response_headers, it));
				}
				nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "\r\n");
				nbytes += snprintf(buf + nbytes, sizeof(buf) - nbytes, "%s", response_body ? response_body : "");

				mget_tcp_write(tcp, buf, nbytes);
			}
			mget_tcp_close(&tcp);
		} else
			mget_info_printf(_("Failed to get connection\n"));
	}

	return NULL;
}

void mget_test_stop_http_server(void)
{
	char cmd[128];

	mget_vector_free(&response_headers);

	if (chdir("..") != 0)
		mget_error_printf(_("Failed to chdir ..\n"));

	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
	if (system(cmd) != 0)
		mget_error_printf(_("Failed to remove tmpdir %s\n"), tmpdir);

	// free resources - needed for valgrind testing
	mget_tcp_deinit(&parent_tcp);
	mget_global_deinit();
}

void mget_test_start_http_server(int first_key, ...)
{
	int rc, key;
	va_list args;

	mget_global_init(
//		MGET_DEBUG_STREAM, stderr,
		MGET_ERROR_STREAM, stderr,
//		MGET_INFO_STREAM, stdout,
		NULL);

	va_start(args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case MGET_TEST_RESPONSE_BODY:
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
		case MGET_TEST_EXPECTED_REQUEST_HEADER:
			break;
		default:
			mget_error_printf(_("Unknown option %d\n"), key);
		}
	}
	va_end(args);

	atexit(mget_test_stop_http_server);

	snprintf(tmpdir, sizeof(tmpdir), ".test_%d",getpid());

	if (mkdir(tmpdir, 0755) != 0)
		mget_error_printf_exit(_("Failed to create tmpdir (%d)\n"), errno);

	if (chdir(tmpdir) != 0)
		mget_error_printf_exit(_("Failed to change to tmpdir (%d)\n"), errno);

	parent_tcp=mget_tcp_init();

	mget_tcp_set_timeout(parent_tcp, -1); // INFINITE timeout

	if (mget_tcp_listen(parent_tcp, "localhost", NULL, 5) != 0)
		exit(1);

	server_port = mget_tcp_get_local_port(parent_tcp);

	// init thread attributes
	if ((rc = mget_thread_start(&server_tid, _server_thread, NULL, 0)) != 0)
		mget_error_printf_exit(_("Failed to start downloader, error %d\n"), rc);
}

void mget_test(int first_key, ...)
{
	char cmd[1024];
	const char
		*request_url = "index.html",
		*expected_file = NULL,
		*expected_file_content = "",
		*options="";
	int
		rc,
		expected_error_code = 0;

	int key;
	va_list args;

	va_start (args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case MGET_TEST_NAME:
			mget_info_printf("Test '%s'\n", va_arg(args, const char *));
			break;
		case MGET_TEST_REQUEST_URL:
			request_url = va_arg(args, const char *);
			break;
		case MGET_TEST_EXPECTED_FILE:
			expected_file = va_arg(args, const char *);
			break;
		case MGET_TEST_EXPECTED_FILE_CONTENT:
			expected_file_content = va_arg(args, const char *);
			break;
		case MGET_TEST_EXPECTED_ERROR_CODE:
			expected_error_code = va_arg(args, int);
			break;
		case MGET_TEST_OPTIONS:
			options = va_arg(args, const char *);
			break;
		default:
			mget_error_printf(_("Unknown option %d\n"), key);
		}
	}

	snprintf(cmd, sizeof(cmd), "../../src/mget -q %s http://localhost:%d/%s", options, server_port, request_url);
	if ((rc = system(cmd)) != expected_error_code)
		mget_error_printf_exit(_("Unexpected error code %d, expected %d\n"), rc, expected_error_code);

	if (expected_file) {
		struct stat st;

		if (stat(expected_file, &st) != 0) {
			mget_error_printf_exit(_("Missing expected file %s/%s\n"), tmpdir, expected_file);
		} else if (expected_file_content) {
			int fd;
			char content[st.st_size];

			if ((fd = open(expected_file, O_RDONLY)) != -1) {
				ssize_t nbytes = read(fd, content, st.st_size);
				close(fd);

				if (nbytes != st.st_size)
					mget_error_printf_exit(_("Failed to read %zd bytes from file %s/%s\n"), st.st_size, tmpdir, expected_file);

				if (strlen(expected_file_content) != (size_t)nbytes || memcmp(expected_file_content, content, nbytes) != 0)
					mget_error_printf_exit(_("Unexpected content\n"));
			}
		}
	}
}


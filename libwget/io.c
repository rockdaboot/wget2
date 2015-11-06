/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2015 Free Software Foundation, Inc.
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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * a collection of I/O routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <errno.h>

#ifdef WIN32
#	include <winsock2.h>
#elif defined(HAVE_SYS_POLL_H)
#	include <sys/poll.h>
#elif defined(HAVE_POLL_H)
#	include <poll.h>
#else
#	include <sys/select.h>
#endif

#include <libwget.h>
#include "private.h"

/**
 * SECTION:libwget-io
 * @short_description: I/O helper routines
 * @title: libwget-io
 * @stability: unstable
 * @include: libwget.h
 *
 * Some general I/O helper functions that could be handy for developers.
 *
 */

// similar to getline(), but:
// - using a file descriptor
// - returns line without trailing \n
// *buf holds size_t[2] at it's end'
//
// casts like '(size_t *)(void *)' are to silence clang

ssize_t wget_fdgetline(char **buf, size_t *bufsize, int fd)
{
	ssize_t nbytes = 0;
	size_t *sizep, length = 0;
	char *p;

	if (!*buf || !*bufsize) {
		// first call
		*buf = malloc(*bufsize = 10240);
		sizep = (size_t *)(void *)(*buf + *bufsize - 2 * sizeof(size_t));
		sizep[0] = sizep[1] = 0;
	} else {
		sizep = (size_t *)(void*)(*buf + *bufsize - 2 * sizeof(size_t));
		if (sizep[1]) {
			// take care of remaining data from last call
			if ((p = memchr(*buf + sizep[0], '\n', sizep[1]))) {
				*p++ = 0;
				length = p - (*buf + sizep[0]);
				if (sizep[0])
					memmove(*buf, *buf + sizep[0], length); // copy line to beginning of buffer
				sizep[0] += length; // position of extra chars
				sizep[1] -= length; // number of extra chars
				return length - 1; // length of line in *buf
			}

			length = sizep[1];
			memmove(*buf, *buf + sizep[0], length + 1);
			sizep[0] = sizep[1] = 0;
		} else **buf = 0;
	}

	while ((nbytes = read(fd, *buf + length, *bufsize - 2 * sizeof(size_t) - length - 1)) > 0) {
		length += nbytes;
		if ((p = memchr(*buf + length - nbytes, '\n', nbytes))) {
			*p++ = 0;
			sizep[0] = p - *buf; // position of extra chars
			sizep[1] = length - sizep[0]; // number of extra chars
			return sizep[0] - 1; // length of line in *buf
		}

		if (length >= *bufsize - 2 * sizeof(size_t) - 1) {
			ptrdiff_t off = ((char *)sizep)-*buf;
			size_t *old;

			*buf = xrealloc(*buf, *bufsize = *bufsize * 2);
			old = (size_t *)(void *)(*buf + off);
			sizep = (size_t *)(void *)(*buf + *bufsize - 2 * sizeof(size_t));
			sizep[0] = old[0];
			sizep[1] = old[1];
		}
	}

	if (nbytes == -1 && errno != EAGAIN) {
		// file/socket descriptor is broken
		// if (errno != EBADF)
		// 	error_printf(_("%s: Failed to read, error %d\n"), __func__, errno);
	}

	if (length) {
		if ((*buf)[length - 1] == '\n')
			(*buf)[length - 1] = 0;
		else
			(*buf)[length] = 0;
		return length;
	} else **buf = 0;

	return -1;
}

ssize_t wget_getline(char **buf, size_t *bufsize, FILE *fp)
{
	ssize_t nbytes = 0;
	size_t *sizep, length = 0;
	char *p;

	if (!*buf || !*bufsize) {
		// first call
		*buf = xmalloc(*bufsize = 10240);
		sizep = (size_t *)(void *)(*buf + *bufsize - 2 * sizeof(size_t));
		sizep[0] = sizep[1] = 0;
	} else {
		sizep = (size_t *)(void *)(*buf + *bufsize - 2 * sizeof(size_t));
		if (sizep[1]) {
			// take care of remaining data from last call
			if ((p = memchr(*buf + sizep[0], '\n', sizep[1]))) {
				*p++ = 0;
				length = p - (*buf + sizep[0]);
				if (sizep[0])
					memmove(*buf, *buf + sizep[0], length); // copy line to beginning of buffer
				sizep[0] += length; // position of extra chars
				sizep[1] -= length; // number of extra chars
				return length - 1; // length of line in *buf
			}

			length = sizep[1];
			memmove(*buf, *buf + sizep[0], length + 1);
			sizep[0] = sizep[1] = 0;
		} else **buf = 0;
	}

	while ((nbytes = fread(*buf + length, 1, *bufsize - 2 * sizeof(size_t) - length - 1, fp)) > 0) {
		length += nbytes;
		if ((p = memchr(*buf + length - nbytes, '\n', nbytes))) {
			*p++ = 0;
			sizep[0] = p - *buf; // position of extra chars
			sizep[1] = length - sizep[0]; // number of extra chars
			return sizep[0] - 1; // length of line in *buf
		}

		if (length >= *bufsize - 2 * sizeof(size_t) - 1) {
			ptrdiff_t off = ((char *)sizep)-*buf;
			size_t *old;

			*buf = xrealloc(*buf, *bufsize = *bufsize * 2);
			old = (size_t *)(void *)(*buf + off);
			sizep = (size_t *)(void *)(*buf + *bufsize - 2 * sizeof(size_t));
			sizep[0] = old[0];
			sizep[1] = old[1];
		}
	}

	if (nbytes == -1 && errno != EAGAIN) {
		// socket is broken
		// if (errno != EBADF)
		//	error_printf(_("%s: Failed to read, error %d\n"), __func__, errno);
	}

	if (length) {
		if ((*buf)[length - 1] == '\n')
			(*buf)[length - 1] = 0;
		else
			(*buf)[length] = 0;
		return length;
	} else **buf = 0;

	return -1;
}

/**
 * wget_ready_2_transfer:
 * @fd: File descriptor to wait for.
 * @timeout: Max. duration in milliseconds to wait.
 * A value of 0 means the function returns immediately.
 * A value of -1 means infinite timeout.
 *
 * Wait for a file descriptor to become ready to read or write.
 *
 * Returns:
 * -1 on error.
 * 0 on timeout. The file descriptor is not ready for reading nor writing.
 * >0 The file descriptor is ready for reading or writing. Check for
 * the bitwise or'ing of WGET_IO_WRITABLE and WGET_IO_WRITABLE.
 *
 */
#ifdef POLLIN
int wget_ready_2_transfer(int fd, int timeout, short mode)
{
	struct pollfd pollfd;
	int rc;

	pollfd.fd = fd;
	pollfd.events = 0;
	pollfd.revents = 0;

	if (mode & WGET_IO_READABLE)
		pollfd.events |= POLLIN;
	if (mode & WGET_IO_WRITABLE)
		pollfd.events |= POLLOUT;

	// wait for socket to be ready to read or write
	if ((rc = poll(&pollfd, 1, timeout)) <= 0)
		return rc;

	mode = 0;
	if (pollfd.revents & POLLIN)
		mode |= WGET_IO_READABLE;
	if (pollfd.revents & POLLOUT)
		mode |= WGET_IO_WRITABLE;

	return mode;
}
#else
int wget_ready_2_transfer(int fd, int timeout, int mode)
{
	// 0: no timeout / immediate
	// -1: INFINITE timeout
	// >0: number of milliseconds to wait
	if (timeout) {
		fd_set fdset;
		struct timeval tmo = { timeout / 1000, (timeout % 1000) * 1000 };
		int rc;

		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);

		if (mode == WGET_IO_READABLE) {
			if (mode == WGET_IO_WRITABLE)
				rc = select(fd + 1, &fdset, &fdset, NULL, &tmo);
			else
				rc = select(fd + 1, &fdset, NULL, NULL, &tmo);
		} else {
			rc = select(fd + 1, NULL, &fdset, NULL, &tmo);
		}

		if (rc <= 0)
			return rc;
	}

	return 1;
}
#endif

/**
 * wget_ready_2_read:
 * @fd: File descriptor to wait for.
 * @timeout: Max. duration in milliseconds to wait.
 * A value of 0 means the function returns immediately.
 * A value of -1 means infinite timeout.
 *
 * Wait for a file descriptor to become ready to read.
 *
 * Returns:
 * -1 on error.
 * 0 on timeout. The file descriptor is not ready for reading.
 * 1 on success. The file descriptor is ready for reading.
 */
int wget_ready_2_read(int fd, int timeout)
{
	return wget_ready_2_transfer(fd, timeout, WGET_IO_READABLE) > 0;
}

/**
 * wget_ready_2_write:
 * @fd: File descriptor to wait for.
 * @timeout: Max. duration in milliseconds to wait.
 * A value of 0 means the function returns immediately.
 * A value of -1 means infinite timeout.
 *
 * Wait for a file descriptor to become ready to write.
 *
 * Returns:
 * -1 on error.
 * 0 on timeout. The file descriptor is not ready for reading.
 * 1 on success. The file descriptor is ready for reading.
 */
int wget_ready_2_write(int fd, int timeout)
{
	return wget_ready_2_transfer(fd, timeout, WGET_IO_WRITABLE) > 0;
}

char *wget_read_file(const char *fname, size_t *size)
{
	int fd;
	ssize_t nread;
	char *buf = NULL;

	if (!fname)
		return NULL;

	if (strcmp(fname,"-")) {
		if ((fd = open(fname, O_RDONLY)) != -1) {
			struct stat st;

			if (fstat(fd, &st) == 0) {
				off_t total = 0;

				buf = xmalloc(st.st_size + 1);

				while (total < st.st_size && (nread = read(fd, buf + total, st.st_size - total)) > 0) {
					total += nread;
				}
				buf[total] = 0;

				if (size)
					*size = total;

				if (total != st.st_size)
					error_printf(_("WARNING: Size of %s changed from %lld to %lld while reading. This may lead to unwanted results !\n"),
						fname, (long long)st.st_size, (long long)total);
			} else
				error_printf(_("Failed to fstat %s\n"), fname);

			close(fd);
		} else
			error_printf(_("Failed to open %s\n"), fname);
	} else {
		// read data from STDIN.
		char tmp[4096];
		wget_buffer_t buffer;
		
		wget_buffer_init(&buffer, NULL, 4096);

		while ((nread = read(STDIN_FILENO, tmp, sizeof(tmp))) > 0) {
			wget_buffer_memcat(&buffer, tmp, nread);
		}

		if (size)
			*size = buffer.length;

		buf = buffer.data;
		buffer.data = NULL;

		wget_buffer_deinit(&buffer);
	}

	return buf;
}

int wget_update_file(const char *fname,
	int (*load_func)(void *, FILE *fp), int (*save_func)(void *, FILE *fp), void *context)
{
	FILE *fp;
	const char *tmpdir, *p, *basename;
	int lockfd, fd;

	char tmpfile[strlen(fname) + 6 + 1];
	snprintf(tmpfile, sizeof(tmpfile), "%sXXXXXX", fname);

	// find out system temp directory
	if (!(tmpdir = getenv("TMPDIR")) && !(tmpdir = getenv("TMP"))
		&& !(tmpdir = getenv("TEMP")) && !(tmpdir = getenv("TEMPDIR")))
		tmpdir = "/tmp";

	if (*fname && (p = strrchr(fname + 1, '/')))
		basename = p + 1;

	// create a per-usr tmp file name for HSTS
	char lockfile[strlen(tmpdir) + strlen(basename) + 32];
	snprintf(lockfile, sizeof(lockfile), "%s/%s_lck_%d", tmpdir, basename, getuid());

	// create & open the lock file
	if ((lockfd = creat(lockfile, 0644)) == -1) {
		error_printf(_("Failed to create '%s' (%d)\n"), lockfile, errno);
		return -1;
	}

	// set the lock
	if (flock(lockfd, LOCK_EX) == -1) {
		close(lockfd);
		error_printf(_("Failed to lock '%s' (%d)\n"), lockfile, errno);
		return -1;
	}

	if (load_func) {
		// open fname for reading
		if (!(fp = fopen(fname, "r"))) {
			if (errno != ENOENT) {
				close(lockfd);
				error_printf(_("Failed to read open '%s' (%d)\n"), fname, errno);
				return -1;
			}
		}

		if (fp) {
			// read fname data
			if (load_func(context, fp)) {
				close(lockfd);
				return -1;
			}

			fclose(fp);
		}
	}

	if (save_func) {
		// creat & open temp file to write data into
		if ((fd = mkstemp(tmpfile)) == -1) {
			close(lockfd);
			error_printf(_("Failed to open tmpfile '%s' (%d)\n"), tmpfile, errno);
			return -1;
		}

		// open the output stream from fd
		if (!(fp = fdopen(fd, "w"))) {
			unlink(tmpfile);
			close(fd);
			close(lockfd);
			error_printf(_("Failed to write open '%s' (%d)\n"), tmpfile, errno);
			return -1;
		}

		// write into temp file
		if (save_func(context, fp)) {
			unlink(tmpfile);
			fclose(fp);
			close(lockfd);
			return -1;
		}

		// write buffers and close temp file
		if (fclose(fp)) {
			unlink(tmpfile);
			close(lockfd);
			error_printf(_("Failed to write/close '%s' (%d)\n"), tmpfile, errno);
			return -1;
		}

		// rename written file (now complete without errors) to FNAME
		if (rename(tmpfile, fname) == -1) {
			close(lockfd);
			error_printf(_("Failed to rename '%s' to '%s' (%d)\n"), tmpfile, fname, errno);
			error_printf(_("Take manually care for '%s'\n"), tmpfile);
			return -1;
		}
	}

	close(lockfd);

	debug_printf("Successfully updated '%s'.\n", fname);
	return 0;
}

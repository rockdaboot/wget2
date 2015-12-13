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

static ssize_t __read(const void *f, char *dst, size_t len)
{
	FILE *fp = (FILE *)f;
	ssize_t ret = (ssize_t)fread(dst, 1, len, fp);
	if (ferror(fp))
		return -1;
	return ret;
}

static ssize_t __readfd(const void *f, char *dst, size_t len)
{
	int *fd = (int *)f;
	return read(*fd, dst, len);
}

static ssize_t wget_getline_internal(char **buf, size_t *bufsize,
		       const void *f,
		       ssize_t (*reader)(const void *f, char *dst, size_t len))
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
		} else
			**buf = 0;
	}

	while ((nbytes = reader(f, *buf + length, *bufsize - 2 * sizeof(size_t) - length - 1)) > 0) {
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
		if (errno != EBADF)
			error_printf(_("%s: Failed to read, error %d\n"), __func__, errno);
	}

	if (length) {
		if ((*buf)[length - 1] == '\n')
			(*buf)[length - 1] = 0;
		else
			(*buf)[length] = 0;
		return length;
	} else
		**buf = 0;

	return -1;
}


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

/**
 * wget_fdgetline:
 * @buf: a pointer to a pointer that will be set up by the function to point to the read line
 * @bufsize: pointer to a variable where the length of the read line will be put
 * @fd: file descriptor for an open file
 *
 * Behaves identically as wget_getline(), but uses a file descriptor instead of a stream.
 *
 * Returns:
 * the length of the last line read
 */
ssize_t wget_fdgetline(char **buf, size_t *bufsize, int fd)
{
	return wget_getline_internal(buf, bufsize, (void *)&fd, __readfd);
}

/**
 * wget_getline:
 * @buf: a pointer to a pointer that will be set up by the function to point to the read line
 * @bufsize: pointer to a variable where the length of the read line will be put
 * @fp: pointer to an open file's stream handle (`FILE *`)
 *
 * This function will read a line from the open file handle @fp. This function reads input characters
 * until either a newline character (`\n`) is found or EOF is reached. A block of memory large enough to hold the read line
 * will be implicitly allocated by the function, and its address placed at the pointer pointed to by @buf.
 * The length of the aforementioned memory block will be stored in the variable pointed at by @bufsize.
 *
 * The caller is not expected to allocate memory as that will be automatically done by wget_getline(),
 * but it is responsibility of the caller free the memory allocated by a previous invocation of this function.
 * The caller is also responsible for opening and closing the file to read from.
 *
 * Subsequent calls to wget_getline() that use the same block of memory allocated by previous calls (that is,
 * the caller did not free the buffer returned by a previous call to wget_getline()) will try to reuse as much as possible
 * from the available memory.
 * The block of memory allocated by wget_getline() may be larger than the length of the line read, and might even contain additional lines
 * in it. When wget_getline() returns, the contents of the buffer (pointed at by @buf) are guaranteed to start with the first
 * character of the last line read, and such line is also guaranteed to end with a NULL termination character (`\0`).
 * The length of the last read line will be returned by wget_getline(), whereas the actual length of the buffer will be placed in the variable
 * pointed at by @bufsize.
 * The newline character (`\n`) will not be included in the last read line.
 *
 * Returns:
 * the length of the last line read
 */
ssize_t wget_getline(char **buf, size_t *bufsize, FILE *fp)
{
	return wget_getline_internal(buf, bufsize, (void *)fp, __read);
}

/**
 * wget_ready_2_transfer:
 * @fd: File descriptor to wait for.
 * @timeout: Max. duration in milliseconds to wait.
 * @mode: either `WGET_IO_WRITABLE` or `WGET_IO_READABLE`.
 * A value of 0 means the function returns immediately.
 * A value of -1 means infinite timeout.
 *
 * Wait for a file descriptor to become ready to read or write.
 *
 * Returns:
 * -1 on error.
 * 0 on timeout. The file descriptor is not ready for reading or writing.
 * &gt;0 The file descriptor is ready for reading or writing. Check for
 * the bitwise or of `WGET_IO_WRITABLE` and `WGET_IO_READABLE`.
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

/**
 * wget_read_file:
 * @fname: the name of the file to read from, or a dash (`-`) to read from STDIN.
 * @size: pointer to a variable where the length of the contents read will be stored.
 *
 * Reads the content of a file, or from STDIN.
 * When reading from STDIN, the behavior is the same as for regular files: input is read
 * until an EOF character is found.
 *
 * Memory will be accordingly allocated by wget_read_file() and a pointer to it returned when the read finishes,
 * but the caller is responsible for freeing that memory.
 * The length of the allocated block of memory, which is guaranteed to be the same as the length of the data read,
 * will be placed in the variable pointed at by @size.
 *
 * The read data is guaranteed to be appended a NULL termination character (`\0`).
 *
 * Returns:
 * pointer to the read data, as a NULL-terminated C string
 */
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

/**
 * wget_update_file:
 * @fname: file name to update
 * @load_func: pointer to the loader function
 * @save_func: pointer to the saver function
 * @context: context data
 *
 * This function updates the file named @fname atomically. It lets two caller-provided functions do the actual updating.
 * A lock file is created first under `/tmp` to ensure exclusive access to the file. Other processes attempting to call
 * wget_update_file() with the same @fname parameter will block until the current calling process has finished (that is,
 * until wget_update_file() has returned).
 * Then, the file is opened with read access first, and the @load_func function is called. When it returns, the file is closed
 * and opened again with write access, and the @save_func function is called.
 * Both callback functions are passed the context data @context, and a stream descriptor for the file.
 * If either function @load_func or @save_func returns a non-zero value, wget_update_file() closes the file and returns -1,
 * performing no further actions.
 *
 * Returns:
 * 0 on success, or -1 on error
 */
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

	if (*fname && (p = strrchr(fname, '/')))
		basename = p + 1;
	else
		basename = fname;

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

		debug_printf("Successfully updated '%s'.\n", fname);
	}

	close(lockfd);

	return 0;
}

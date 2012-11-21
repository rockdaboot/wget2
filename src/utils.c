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
 * a collection of utility routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 * 31.05.2012               added popen3() and fd_popen3()
 * 07.11.2012               added memdup()
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "xalloc.h"
#include "log.h"
#include "utils.h"

// similar to getline(), but:
// - using a file descriptor
// - returns line without trailing \n
// *buf holds size_t[2] at it's end'
//
// casts like '(size_t *)(void *)' are to silence clang

ssize_t fdgetline0(char **buf, size_t *bufsize, int fd)
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

	if (nbytes == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
		// socket is broken
		if (errno != EBADF)
			err_printf(_("%s: Failed to read, error %d\n"), __func__, errno);
	}

	if (length) {
		(*buf)[length - 1] = 0;
		return length;
	} else **buf = 0;

	return -1;
}

ssize_t getline(char **buf, size_t *bufsize, FILE *fp)
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

	if (nbytes == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
		// socket is broken
		if (errno != EBADF)
			err_printf(_("%s: Failed to read, error %d\n"), __func__, errno);
	}

	if (length) {
		(*buf)[length - 1] = 0;
		return length;
	} else **buf = 0;

	return -1;
}

FILE *vpopenf(const char *type, const char *fmt, va_list args)
{
	FILE *fp = NULL;
	char sbuf[4096], *bufp = NULL;
	int len;
	va_list args2;

	// vsnprintf destroys args, so we need a copy for the fallback cases
	va_copy(args2, args);

	// first try without malloc
	len = vsnprintf(sbuf, sizeof(sbuf), fmt, args);

	if (len >= 0 && len < (int)sizeof(sbuf)) {
		// message fits into buf - most likely case
		bufp = sbuf;
	} else if (len >= (int)sizeof(sbuf)) {
		// POSIX compliant or glibc >= 2.1
		bufp = xmalloc(len + 1);
		vsnprintf(bufp, len + 1, fmt, args2);
	} else if (len == -1) {
		// oldstyle with ugly try-and-error fallback (maybe just truncate the msg ?)
		size_t size = sizeof(sbuf);

		do {
			xfree(bufp);
			bufp = xmalloc((size *= 2));
			va_copy(args, args2);
			len = vsnprintf(bufp, size, fmt, args);
		} while (len == -1);
	}

	fp = popen(bufp, type);
	if (bufp != sbuf)
		xfree(bufp);

	return fp;
}

FILE *popenf(const char *type, const char *fmt, ...)
{
	FILE *fp;
	va_list args;

	va_start(args, fmt);
	fp = vpopenf(type, fmt, args);
	va_end(args);

	return fp;
}

pid_t fd_popen3(int *fdin, int *fdout, int *fderr, const char *const *argv)
{
	int pipefd_in[2]; // child's STDIN
	int pipefd_out[2]; // child's STDOUT
	int pipefd_err[2]; // child's STDERR
	pid_t pid;

	// create a pipe. the child writes into it and the parent read from it.
	// pipefd[0]=reader pipefd[1]=writer
	if (fdin && pipe(pipefd_in) == -1) {
		err_printf(_("Failed to create pipe for STDIN on %s\n"), argv[0]);
		return -1;
	}
	if (fdout && pipe(pipefd_out) == -1) {
		err_printf(_("Failed to create pipe for STDOUT on %s\n"), argv[0]);
		if (fdin) {
			close(pipefd_in[0]);
			close(pipefd_in[1]);
		}
		return -1;
	}
	if (fderr && fderr != fdout && pipe(pipefd_err) == -1) {
		err_printf(_("Failed to create pipe for STDERR on %s\n"), argv[0]);
		if (fdin) {
			close(pipefd_in[0]);
			close(pipefd_in[1]);
		}
		if (fdout) {
			close(pipefd_out[0]);
			close(pipefd_out[1]);
		}
		return -1;
	}

	if ((pid = fork()) == 0) {
		if (fdin) {
			close(pipefd_in[1]); // the STDIN writer is not needed by the child

			// redirect STDIN to reader
			if (dup2(pipefd_in[0], STDIN_FILENO) == -1)
				err_printf_exit(_("Failed to dup2(%d,%d) (%d)\n"), pipefd_in[0], STDIN_FILENO, errno);

			close(pipefd_in[0]); // the old STDIN reader is not needed any more
		}

		if (fdout) {
			close(pipefd_out[0]); // the STDOUT reader is not needed by the child

			// redirect STDOUT to writer
			if (dup2(pipefd_out[1], STDOUT_FILENO) == -1)
				err_printf_exit(_("Failed to dup2(%d,%d) (%d)\n"), pipefd_out[1], STDOUT_FILENO, errno);

			close(pipefd_out[1]); // the old STDOUT writer is not needed any more
		}

		if (fderr) {
			if (fderr != fdout) {
				close(pipefd_err[0]); // the STDERR reader is not needed by the child

				// redirect STDERR to writer
				if (dup2(pipefd_err[1], STDERR_FILENO) == -1)
					err_printf_exit(_("Failed to dup2(%d,%d) (%d)\n"), pipefd_err[1], STDERR_FILENO, errno);

				close(pipefd_err[1]); // the old STDERR writer is not needed any more
			} else {
				// redirect STDERR to STDOUT
				if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1)
					exit(EXIT_FAILURE);
			}
		}

		execvp(argv[0], (char *const *)argv); // does only return on error
		//		err_printf(_("Failed to execute %s (%d)\n"),argv[0],errno);
		exit(EXIT_FAILURE);
	} else if (pid < 0) {
		// fork error
		if (fdin) {
			close(pipefd_in[0]);
			close(pipefd_in[1]);
		}
		if (fdout) {
			close(pipefd_out[0]);
			close(pipefd_out[1]);
		}
		if (fderr && fderr != fdout) {
			close(pipefd_err[0]);
			close(pipefd_err[1]);
		}
		err_printf(_("Failed to fork '%s'\n"), argv[0]);
		return pid;
	}

	// parent
	if (fdin) {
		close(pipefd_in[0]); // the STDIN reader is not needed by the parent
		*fdin = pipefd_in[1];
	}
	if (fdout) {
		close(pipefd_out[1]); // the STDOUT writer is not needed by the parent
		*fdout = pipefd_out[0];
	}
	if (fderr && fderr != fdout) {
		close(pipefd_err[1]); // the STDERR writer is not needed by the parent
		*fderr = pipefd_err[0];
	}

	return pid;
}

// extended popen to have control over the childs STDIN, STDOUT and STDERR
// NULL to ignore childs STDxxx
// if fpout==fperr STDERR will be redirected to STDOUT
// fpin: childs stdin (that's where the calling process can write data into)
// fpout: childs stdout (that's where the calling process reads data from)
// fperr: childs stderr (that's where the calling process reads error messages from)
// argv: argument to execvp(), e.g. const char *argv[]={"ls","-la",NULL};

pid_t popen3(FILE **fpin, FILE **fpout, FILE **fperr, const char *const *argv)
{
	int fdin, fdout, fderr = -1;
	pid_t pid;

	if (fpin) *fpin = NULL;
	if (fpout) *fpout = NULL;
	if (fperr) *fperr = NULL;

	if ((pid = fd_popen3(fpin ? &fdin : NULL, fpout ? &fdout : NULL, fperr ? (fperr != fpout ? &fderr : &fdout) : NULL, argv)) > 0) {
		if (fpin) *fpin = fdopen(fdin, "w");
		if (fpout) *fpout = fdopen(fdout, "r");
		if (fperr && fperr != fpout) *fperr = fdopen(fderr, "r");
	}

	return pid;
}

// strlcpy is a BSD function that I really like.
// it is the same as snprintf(dst,size,"%s",src),
// but ways faster

size_t strlcpy(char *dst, const char *src, size_t size)
{
	const char *old = src;

	// Copy as many bytes as will fit */
	if (size) {
		while (--size) {
			if (!(*dst++ = *src++))
				return src - old - 1;
		}

		*dst = 0;
	}

	while (*src++);
	return src - old - 1;
}

// strcmp which also accepts NULL values

int null_strcmp(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strcmp(s1, s2);
	}
}

// strcasecmp which also accepts NULL values

int null_strcasecmp(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strcasecmp(s1, s2);
	}
}

void buffer_to_hex(const unsigned char *src, size_t src_len, char *dst, size_t dst_size)
{
	size_t it;
	int adjust = 0, c;

	if (dst_size == 0)
		return;

	if (src_len * 2 >= dst_size) {
		src_len = (dst_size - 1) / 2;
		adjust = 1;
	}

	for (it = 0; it < src_len; it++, src++) {
		*dst++ = (c = (*src >> 4)) >= 10 ? c + 'a' - 10 : c + '0';
		*dst++ = (c = (*src & 0xf)) >= 10 ? c + 'a' - 10 : c + '0';
	}
	if (adjust && (dst_size & 1) == 0)
		*dst++ = (c = (*src >> 4)) >= 10 ? c + 'a' - 10 : c + '0';

	*dst = 0;
}

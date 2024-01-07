/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * a collection of pipe/popen routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#ifndef _WIN32

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <wget.h>
#include "private.h"


FILE *wget_vpopenf(const char *type, const char *fmt, va_list args)
{
	FILE *fp = NULL;
	char sbuf[1024];
	wget_buffer buf;

	if (!type || !fmt)
		return NULL;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_vprintf(&buf, fmt, args);

	fp = popen(buf.data, type);

	wget_buffer_deinit(&buf);

	return fp;
}

FILE *wget_popenf(const char *type, const char *fmt, ...)
{
	FILE *fp;
	va_list args;

	va_start(args, fmt);
	fp = wget_vpopenf(type, fmt, args);
	va_end(args);

	return fp;
}

pid_t wget_fd_popen3(int *fdin, int *fdout, int *fderr, const char *const *argv)
{
	int pipefd_in[2]; // child's STDIN
	int pipefd_out[2]; // child's STDOUT
	int pipefd_err[2]; // child's STDERR
	pid_t pid;

	if (!argv)
		return -1;

	// create a pipe. the child writes into it and the parent read from it.
	// pipefd[0]=reader pipefd[1]=writer
	if (fdin && pipe(pipefd_in) == -1) {
		error_printf(_("Failed to create pipe for STDIN on %s\n"), argv[0]);
		return -1;
	}
	if (fdout && pipe(pipefd_out) == -1) {
		error_printf(_("Failed to create pipe for STDOUT on %s\n"), argv[0]);
		if (fdin) {
			close(pipefd_in[0]);
			close(pipefd_in[1]);
		}
		return -1;
	}
	if (fderr && fderr != fdout && pipe(pipefd_err) == -1) {
		error_printf(_("Failed to create pipe for STDERR on %s\n"), argv[0]);
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
				error_printf_exit(_("Failed to dup2(%d,%d) (%d)\n"), pipefd_in[0], STDIN_FILENO, errno);

			close(pipefd_in[0]); // the old STDIN reader is not needed any more
		}

		if (fdout) {
			close(pipefd_out[0]); // the STDOUT reader is not needed by the child

			// redirect STDOUT to writer
			if (dup2(pipefd_out[1], STDOUT_FILENO) == -1)
				error_printf_exit(_("Failed to dup2(%d,%d) (%d)\n"), pipefd_out[1], STDOUT_FILENO, errno);

			close(pipefd_out[1]); // the old STDOUT writer is not needed any more
		}

		if (fderr) {
			if (fderr != fdout) {
				close(pipefd_err[0]); // the STDERR reader is not needed by the child

				// redirect STDERR to writer
				if (dup2(pipefd_err[1], STDERR_FILENO) == -1)
					error_printf_exit(_("Failed to dup2(%d,%d) (%d)\n"), pipefd_err[1], STDERR_FILENO, errno);

				close(pipefd_err[1]); // the old STDERR writer is not needed any more
			} else {
				// redirect STDERR to STDOUT
				if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1)
					exit(EXIT_FAILURE);
			}
		}

		execvp(argv[0], (char *const *)argv); // does only return on error
		//		error_printf(_("Failed to execute %s (%d)\n"),argv[0],errno);
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
		error_printf(_("Failed to fork '%s'\n"), argv[0]);
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

// extended popen to have control over the child's STDIN, STDOUT and STDERR
// NULL to ignore child's STDxxx
// if fpout==fperr STDERR will be redirected to STDOUT
// fpin: child's stdin (that's where the calling process can write data into)
// fpout: child's stdout (that's where the calling process reads data from)
// fperr: child's stderr (that's where the calling process reads error messages from)
// argv: argument to execvp(), e.g. const char *argv[]={"ls","-la",NULL};

pid_t wget_popen3(FILE **fpin, FILE **fpout, FILE **fperr, const char *const *argv)
{
	int fdin = -1, fdout = -1, fderr = -1;
	pid_t pid;

	if (fpin) *fpin = NULL;
	if (fpout) *fpout = NULL;
	if (fperr) *fperr = NULL;

	if ((pid = wget_fd_popen3(fpin ? &fdin : NULL, fpout ? &fdout : NULL, fperr ? (fperr != fpout ? &fderr : &fdout) : NULL, argv)) > 0) {
		if (fpin) *fpin = fdopen(fdin, "w");
		if (fpout) *fpout = fdopen(fdout, "r");
		if (fperr && fperr != fpout) *fperr = fdopen(fderr, "r");
	}

	return pid;
}

#endif

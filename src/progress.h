/*
 * Copyright(c) 2014 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for Progress routines and structures
 *
 * Changelog
 * 23/07/2016	Darshit Shah	created
 *
 */


#ifndef _WGET_PROGRESS_H
# define _WGET_PROGRESS_H

#include "job.h"
#include "wget.h"

#define DEFAULT_SCREEN_WIDTH 70

#define MINIMUM_SCREEN_WIDTH 45

// the following is just needed for the progress bar
struct _body_callback_context {
	DOWNLOADER *downloader;
	wget_buffer_t *body;
	int outfd;
	size_t max_memory;
	off_t length;
	bool head;
	wget_bar_ctx bar;
};

#endif /* _WGET_PROGRESS_H */

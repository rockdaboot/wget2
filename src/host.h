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
 * Header file for HOST stuff
 *
 * Changelog
 * 10.09.2013  Tim Ruehsen  created
 *
 */

#ifndef _MGET_HOST_H
#define _MGET_HOST_H

#include <stdarg.h>

#include "job.h"

struct JOB;
typedef struct JOB JOB;
typedef struct ROBOTS ROBOTS;

// everything host/domain specific should go here
typedef struct {
	const char
		*scheme,
		*host;
	JOB
		*robot_job;
	ROBOTS
		*robots;
} HOST;

#endif /* _MGET_HOST_H */

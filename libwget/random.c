/*
 * Copyright(c) 2012 Tim Ruehsen
 * Copyright(c) 2016 Free Software Foundation, Inc.
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
 * a multi-thread safe wrapper around random()
 *
 * Changelog
 * 22.01.2016  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <libwget.h>
#include "private.h"

/**
 * \file
 * \brief Random functions
 * \defgroup libwget-random Random functions
 * @{
 *
 * This is wrapper code around srandom() and random() with automatic seeding
 */

static wget_thread_mutex_t mutex = WGET_THREAD_MUTEX_INITIALIZER;
static int seeded;

/**
 * \return Random value between 0 and RAND_MAX
 *
 * This functions wraps around random() to make it thread-safe and seed it on the first use,
 * if not done before by wget_srandom();
 */
long wget_random(void)
{
	long r;

	wget_thread_mutex_lock(&mutex);

	if (!seeded) {
		// seed random generator, used e.g. by Digest Authentication and --random-wait
		srandom(time(NULL) ^ getpid());
		seeded = 1;
	}

	r = random();

	wget_thread_mutex_unlock(&mutex);
	return r;
}

/**
 * \return Seeds the random generator
 *
 * This functions wraps around srandom() to make it thread-safe.
 */
void wget_srandom(unsigned int seed)
{
	wget_thread_mutex_lock(&mutex);

	srandom(seed);
	seeded = 1;

	wget_thread_mutex_unlock(&mutex);
}

/**@}*/

/*
 * Copyright(c) 2013 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * Thread wrapper routines
 *
 * Changelog
 * 02.02.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <errno.h>
#include "timespec.h" // gnulib gettime()
#include <glthread/thread.h>
#include <glthread/lock.h>
#include <glthread/cond.h>

#include <wget.h>
#include "private.h"

struct _wget_thread_st {
	gl_thread_t tid;
};

struct _wget_thread_mutex_st {
	gl_lock_t mutex;
};

struct _wget_thread_cond_st {
	gl_cond_t cond;
};

int wget_thread_mutex_init(wget_thread_mutex_t *mutex)
{
	int rc;
	struct _wget_thread_mutex_st _mutex;

	if ((rc = glthread_lock_init(&_mutex.mutex)) == 0)
		*mutex = wget_memdup(&_mutex, sizeof(_mutex));

	return rc;
}

void wget_thread_mutex_lock(wget_thread_mutex_t mutex)
{
	glthread_lock_lock(&mutex->mutex);
}

void wget_thread_mutex_unlock(wget_thread_mutex_t mutex)
{
	glthread_lock_unlock(&mutex->mutex);
}

int wget_thread_mutex_destroy(wget_thread_mutex_t *mutex)
{
	if (mutex && *mutex) {
		int rc = glthread_lock_destroy(&(*mutex)->mutex);
		xfree(*mutex);
		return rc;
	}
	return -1;
}

int wget_thread_start(wget_thread_t *thread, void *(*start_routine)(void *), void *arg, int flags G_GNUC_WGET_UNUSED)
{
	int rc;
	struct _wget_thread_st _thr;

	if ((rc = glthread_create(&_thr.tid, start_routine, arg)) == 0)
		*thread = wget_memdup(&_thr, sizeof(_thr));

	return rc;
}

int wget_thread_cancel(wget_thread_t thread G_GNUC_WGET_UNUSED)
{
/*
	if (thread && thread->tid)
		return glthread_cancel(thread->tid);

	errno = ESRCH;
	return -1;
*/
	return 0;
}

int wget_thread_kill(wget_thread_t thread G_GNUC_WGET_UNUSED, int sig G_GNUC_WGET_UNUSED)
{
/*	if (thread && thread->tid)
		return glthread_kill(thread->tid, sig);

	errno = ESRCH;
	return -1;
*/
	return 0;
}

int wget_thread_join(wget_thread_t *thread)
{
	if (thread && *thread && (*thread)->tid) {
		int rc = glthread_join((*thread)->tid, NULL);
		xfree(*thread);
		return rc;
	}

	errno = ESRCH;
	return -1;
}

wget_thread_id_t wget_thread_self(void)
{
	return gl_thread_self();
}

int wget_thread_cond_init(wget_thread_cond_t *cond)
{
	int rc;
	struct _wget_thread_cond_st _cond;

	if ((rc = glthread_cond_init(&_cond.cond)) == 0)
		*cond = wget_memdup(&_cond, sizeof(_cond));

	return rc;
}

int wget_thread_cond_signal(wget_thread_cond_t cond)
{
	return glthread_cond_broadcast(&cond->cond);
}

int wget_thread_cond_wait(wget_thread_cond_t cond, wget_thread_mutex_t mutex, long long ms)
{
	if (ms <= 0)
		return glthread_cond_wait(&cond->cond, &mutex->mutex);

	// pthread_cond_timedwait() wants an absolute time
	ms += wget_get_timemillis();

	return glthread_cond_timedwait(&cond->cond, &mutex->mutex, (&(struct timespec){ .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000 }));
}

int wget_thread_cond_destroy(wget_thread_cond_t *cond)
{
	int rc = glthread_cond_destroy(&(*cond)->cond);
	xfree(*cond);
	return rc;
}

bool wget_thread_support(void)
{
	return true;
}

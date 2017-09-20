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

#include <signal.h>
#include <errno.h>
#include "timespec.h" // gnulib gettime()

#include <wget.h>
#include "private.h"

#if USE_POSIX_THREADS || USE_PTH_THREADS

int wget_thread_start(wget_thread_t *thread, void *(*start_routine)(void *), void *arg, int flags G_GNUC_WGET_UNUSED)
{
	int rc;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	// pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	pthread_attr_setschedpolicy(&attr, SCHED_OTHER);

	rc = pthread_create(thread, &attr, start_routine, arg);

	pthread_attr_destroy(&attr);

	return rc;
}

int wget_thread_mutex_init(wget_thread_mutex_t *mutex)
{
	return pthread_mutex_init(mutex, NULL);
}

void wget_thread_mutex_lock(wget_thread_mutex_t *mutex)
{
	pthread_mutex_lock(mutex);
}

void wget_thread_mutex_unlock(wget_thread_mutex_t *mutex)
{
	pthread_mutex_unlock(mutex);
}

int wget_thread_cancel(wget_thread_t thread)
{
	if (thread)
		return pthread_cancel(thread);

	errno = ESRCH;
	return -1;
}

int wget_thread_kill(wget_thread_t thread, int sig)
{
	if (thread)
		return pthread_kill(thread, sig);

	errno = ESRCH;
	return -1;
}

int wget_thread_join(wget_thread_t thread)
{
	if (thread)
		return pthread_join(thread, NULL);

	errno = ESRCH;
	return -1;
}

wget_thread_t wget_thread_self(void)
{
	return pthread_self();
}

int wget_thread_cond_init(wget_thread_cond_t *cond)
{
	return pthread_cond_init(cond, NULL);
}

int wget_thread_cond_signal(wget_thread_cond_t *cond)
{
	return pthread_cond_broadcast(cond);
}

int wget_thread_cond_wait(wget_thread_cond_t *cond, wget_thread_mutex_t *mutex, long long ms)
{
	if (ms <= 0)
		return pthread_cond_wait(cond, mutex);

	// pthread_cond_timedwait() wants an absolute time
	ms += wget_get_timemillis();

	return pthread_cond_timedwait(cond, mutex, &(struct timespec){ .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000 });
}

bool wget_thread_support(void)
{
	return true;
}

#else // USE_POSIX_THREADS || USE_PTH_THREADS

bool wget_thread_support(void)
{
	return false;
}

int wget_thread_start(wget_thread_t *thread, void *(*start_routine)(void *), void *arg, int flags G_GNUC_WGET_UNUSED)
{
	start_routine(arg);
	return 0;
}
int wget_thread_mutex_init(wget_thread_mutex_t *mutex) { return 0; }
void wget_thread_mutex_lock(wget_thread_mutex_t *mutex) { }
void wget_thread_mutex_unlock(wget_thread_mutex_t *mutex) { }
int wget_thread_cancel(wget_thread_t thread) { return 0; }
int wget_thread_kill(wget_thread_t thread, int sig) { return 0; }
int wget_thread_join(wget_thread_t thread) { return 0; }
wget_thread_t wget_thread_self(void) { return 0; }
int wget_thread_cond_init(wget_thread_cond_t *cond) { return 0; }
int wget_thread_cond_signal(wget_thread_cond_t *cond) { return 0; }
int wget_thread_cond_wait(wget_thread_cond_t *cond, wget_thread_mutex_t *mutex, long long ms) { return 0; }

#endif // USE_POSIX_THREADS || USE_PTH_THREADS

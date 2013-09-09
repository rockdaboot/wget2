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
 * Thread wrapper routines
 *
 * Changelog
 * 02.02.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <signal.h>

#include <libmget.h>
#include "private.h"

#ifdef HAVE_LIBPTHREAD

int mget_thread_start(mget_thread_t *thread, void *(*start_routine)(void *), void *arg, int flags G_GNUC_MGET_UNUSED)
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

void mget_thread_mutex_lock(mget_thread_mutex_t *mutex)
{
	pthread_mutex_lock(mutex);
}

void mget_thread_mutex_unlock(mget_thread_mutex_t *mutex)
{
	pthread_mutex_unlock(mutex);
}

int mget_thread_kill(mget_thread_t thread, int sig)
{
	return pthread_kill(thread, sig);
}

int mget_thread_join(mget_thread_t thread)
{
	return pthread_join(thread, NULL);
}

mget_thread_t mget_thread_self(void)
{
	return pthread_self();
}

int mget_thread_cond_init(mget_thread_cond_t *cond)
{
	return pthread_cond_init(cond, NULL);
}

int mget_thread_cond_signal(mget_thread_cond_t *cond)
{
	return pthread_cond_broadcast(cond);
}

int mget_thread_cond_wait(mget_thread_cond_t *cond, mget_thread_mutex_t *mutex)
{
	return pthread_cond_wait(cond, mutex);
}

#else // HAVE_LIBPTHREAD

int mget_thread_start(mget_thread_t *thread, void *(*start_routine)(void *), void *arg, int flags G_GNUC_MGET_UNUSED)
{
	return -1;
}
void mget_thread_mutex_lock(mget_thread_mutex_t *mutex) { }
void mget_thread_mutex_unlock(mget_thread_mutex_t *mutex) { }
int mget_thread_kill(mget_thread_t thread, int sig) { return 0; }
int mget_thread_join(mget_thread_t thread) { return 0; }
mget_thread_t mget_thread_self(void) { return 0; }

#endif // HAVE_LIBPTHREAD

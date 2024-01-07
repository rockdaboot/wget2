/*
 * Copyright (c) 2013 Tim Ruehsen
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
 * Thread wrapper routines
 *
 * Changelog
 * 02.02.2013  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <errno.h>

// silence warnings in gnulib code
#if defined __clang__
  #pragma clang diagnostic ignored "-Wundef"
  #pragma clang diagnostic ignored "-Wshorten-64-to-32"
  #pragma clang diagnostic ignored "-Wconditional-uninitialized"
#elif defined __GNUC__ && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5))
  #pragma GCC diagnostic ignored "-Wundef"
#endif

#include <glthread/thread.h>
#include <glthread/lock.h>
#include <glthread/cond.h>

#include "timespec.h" // gnulib gettime()

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Implementation of multi-threading basic functionality
 * \defgroup libwget-thread Implementation of multi-threading basic functionality
 * @{
 *
 * This is a wrapper around Gnulib's glthread functionality.
 *
 * It currently supports Posix threads (pthreads), GNU Pth threads,
 * Solaris threads and Windows threads.
 */

struct wget_thread_st {
	gl_thread_t tid; //!< thread id
};

struct wget_thread_mutex_st {
	gl_lock_t mutex; //!< mutex
};

struct wget_thread_cond_st {
	gl_cond_t cond; //!< conditional
};

/**
 * \param[in,out] mutex The mutex to initialize
 * \return 0 on success, non-zero on failure
 *
 * Initializes the \p mutex.
 *
 * After usage, a call to wget_thread_mutex_destroy() frees
 * the allocated resources.
 */
int wget_thread_mutex_init(wget_thread_mutex *mutex)
{
	*mutex = wget_malloc(sizeof(struct wget_thread_mutex_st));

	if (!*mutex)
		return WGET_E_MEMORY;

	return glthread_lock_init(&((*mutex)->mutex));
}

/**
 * \param[in,out] mutex The mutex to destroy
 * \return 0 on success, non-zero on failure
 *
 * Free's the \p mutex and it's resources.
 *
 * After calling this function, the \p mutex cannot be used any more.
 */
int wget_thread_mutex_destroy(wget_thread_mutex *mutex)
{
	int rc = glthread_lock_destroy(&(*mutex)->mutex);
	xfree(*mutex);
	return rc;
}

/**
 * \param[in] mutex The mutex to be locked
 *
 * Creates a lock on the \p mutex.
 *
 * To unlock the \p mutex, call wget_thread_mutex_unlock().
 */
void wget_thread_mutex_lock(wget_thread_mutex mutex)
{
	glthread_lock_lock(&mutex->mutex);
}

/**
 * \param[in] mutex The mutex to be unlocked
 *
 * Unlocks the \p mutex.
 */
void wget_thread_mutex_unlock(wget_thread_mutex mutex)
{
	glthread_lock_unlock(&mutex->mutex);
}

/**
 * \param[in,out] cond The conditional to initialize
 * \return 0 on success, non-zero on failure
 *
 * Initializes the conditional \p cond.
 *
 * After usage, a call to wget_thread_cond_destroy() frees
 * the allocated resources.
 */
int wget_thread_cond_init(wget_thread_cond *cond)
{
	*cond = wget_malloc(sizeof(struct wget_thread_cond_st));

	if (!*cond)
		return WGET_E_MEMORY;

	return glthread_cond_init(&((*cond)->cond));
}

/**
 * \param[in,out] cond The conditional to destroy
 * \return 0 on success, non-zero on failure
 *
 * Free's the conditional \p cond and it's resources.
 *
 * After calling this function, \p cond cannot be used any more.
 */
int wget_thread_cond_destroy(wget_thread_cond *cond)
{
	int rc = glthread_cond_destroy(&(*cond)->cond);
	xfree(*cond);
	return rc;
}

/**
 * \param[in] cond The conditional to signal a condition
 * \return 0 on success, non-zero on failure
 *
 * Wakes up one (random) thread that waits on the conditional.
 */
int wget_thread_cond_signal(wget_thread_cond cond)
{
	return glthread_cond_broadcast(&cond->cond);
}

/**
 * \param[in] cond The conditional to wait for
 * \param[in] mutex The mutex needed for thread-safety
 * \param[in] ms The wait timeout in milliseconds
 * \return 0 on success, non-zero on failure
 *
 * Waits for a condition with a max. timeout of \p ms milliseconds.
 *
 * To wait forever use a timeout lower or equal then 0.
 */
int wget_thread_cond_wait(wget_thread_cond cond, wget_thread_mutex mutex, long long ms)
{
	if (ms <= 0)
		return glthread_cond_wait(&cond->cond, &mutex->mutex);

	// pthread_cond_timedwait() wants an absolute time
	struct timespec ts;
	gettime(&ts);
	ms += ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;

	return glthread_cond_timedwait(&cond->cond, &mutex->mutex, &ts);
}

/**
 * \param[out] thread The thread variable to be initialized
 * \param[in] start_routine The thread function to start
 * \param[in] arg The argument given to \p start_routine
 * \param[in] flags Currently unused
 * \return 0 on success, non-zero on failure
 *
 * Start \p start_routine as own thread with argument \p arg.
 */
int wget_thread_start(wget_thread *thread, void *(*start_routine)(void *), void *arg, WGET_GCC_UNUSED int flags)
{
	if (wget_thread_support()) {
		*thread = wget_malloc(sizeof(struct wget_thread_st));

		if (!*thread)
			return WGET_E_MEMORY;

		return glthread_create(&((*thread)->tid), start_routine, arg);
	}

	*thread = NULL;
	start_routine(arg);
	return 0;
}

/**
 * \param[in] thread Thread to cancel
 * \return 0 on success, non-zero on failure
 *
 * Currently a no-op function, since it's not portable.
 */
int wget_thread_cancel(WGET_GCC_UNUSED wget_thread thread)
{
/*
	if (thread && thread->tid)
		return glthread_cancel(thread->tid);

	errno = ESRCH;
	return -1;
*/
	return 0;
}

/**
 * \param[in] thread Thread to send the signal to
 * \param[in] sig Signal to send
 * \return 0 on success, non-zero on failure
 *
 * Currently a no-op function, since it's not portable.
 */
int wget_thread_kill(WGET_GCC_UNUSED wget_thread thread, WGET_GCC_UNUSED int sig)
{
/*	if (thread && thread->tid)
		return glthread_kill(thread->tid, sig);

	errno = ESRCH;
	return -1;
*/
	return 0;
}

/**
 * \param[in] thread Thread to wait for
 * \return 0 on success, non-zero on failure
 *
 * Wait until the \p thread has been stopped.
 *
 * This function just waits - to stop a thread you have take
 * your own measurements.
 */
int wget_thread_join(wget_thread *thread)
{
	if (thread && *thread && (*thread)->tid) {
		int rc = glthread_join((*thread)->tid, NULL);
		xfree(*thread);
		return rc;
	}

	if (wget_thread_support()) {
		errno = ESRCH;
		return -1;
	}

	return 0;
}

/**
 * \return The thread id of the caller.
 *
 */
wget_thread_id wget_thread_self(void)
{
	return (wget_thread_id) gl_thread_self();
}

/**
 * \return Whether libwget supports multi-threading on this platform or not.
 */
bool wget_thread_support(void)
{
#if defined USE_POSIX_THREADS || defined USE_PTH_THREADS || defined USE_SOLARIS_THREADS || defined USE_WINDOWS_THREADS
	return true;
#else
	return false;
#endif
}

/**@}*/

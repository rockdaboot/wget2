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
 * Memory allocation routines
 *
 * Changelog
 * 18.01.2013  Tim Ruehsen  created
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <pthread.h>
#include <stdarg.h>

#include <libmget.h>
#include "private.h"

static int _init;
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;

void mget_global_init(int first_key, ...)
{
	va_list args;
	int key;

	pthread_mutex_lock(&_mutex);

	_init++;

	if (_init) {
		pthread_mutex_unlock(&_mutex);
		return;
	}

	va_start (args, first_key);
	while ((key = va_arg(args, int))) {
		switch (key) {
		case MGET_DEBUG_STREAM:
			mget_logger_set_file(mget_get_logger(MGET_LOGGER_DEBUG), va_arg(args, FILE *));
			break;
		case MGET_DEBUG_FUNC:
			mget_logger_set_func(mget_get_logger(MGET_LOGGER_DEBUG), va_arg(args, void (*)(const char *, size_t)));
			break;
		case MGET_DEBUG_FILE:
			mget_logger_set_filename(mget_get_logger(MGET_LOGGER_DEBUG), va_arg(args, const char *));
			break;
		case MGET_ERROR_STREAM:
			mget_logger_set_file(mget_get_logger(MGET_LOGGER_ERROR), va_arg(args, FILE *));
			break;
		case MGET_ERROR_FUNC:
			mget_logger_set_func(mget_get_logger(MGET_LOGGER_ERROR), va_arg(args, void (*)(const char *, size_t)));
			break;
		case MGET_ERROR_FILE:
			mget_logger_set_filename(mget_get_logger(MGET_LOGGER_ERROR), va_arg(args, const char *));
			break;
		case MGET_INFO_STREAM:
			mget_logger_set_file(mget_get_logger(MGET_LOGGER_INFO), va_arg(args, FILE *));
			break;
		case MGET_INFO_FUNC:
			mget_logger_set_func(mget_get_logger(MGET_LOGGER_INFO), va_arg(args, void (*)(const char *, size_t)));
			break;
		case MGET_INFO_FILE:
			mget_logger_set_filename(mget_get_logger(MGET_LOGGER_INFO), va_arg(args, const char *));
			break;
		default:
			pthread_mutex_unlock(&_mutex);
			mget_error_printf(_("Unknown option %d"), key);
			return;
		}
	}
	va_end(args);

	pthread_mutex_unlock(&_mutex);
}

void mget_global_deinit(void)
{
/*
	pthread_mutex_lock(&_mutex);

	if (_init == 1) {
		// free resources here
	}

	if (_init > 0) _init--;

	pthread_mutex_unlock(&_mutex);
*/
}

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

static struct _CONFIG {
	const char *
		cookie_store;
	char
		cookies_enabled,
		keep_session_cookies;
} _config = {
	.cookies_enabled = 0
};

static int _init;
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;

void mget_global_init(int first_key, ...)
{
	va_list args;
	int key;

	pthread_mutex_lock(&_mutex);

	if (_init++) {
		pthread_mutex_unlock(&_mutex);
		return;
	}

	va_start (args, first_key);
	for (key = first_key; key; key = va_arg(args, int)) {
		switch (key) {
		case MGET_DEBUG_STREAM:
			mget_logger_set_stream(mget_get_logger(MGET_LOGGER_DEBUG), va_arg(args, FILE *));
			break;
		case MGET_DEBUG_FUNC:
			mget_logger_set_func(mget_get_logger(MGET_LOGGER_DEBUG), va_arg(args, void (*)(const char *, size_t)));
			break;
		case MGET_DEBUG_FILE:
			mget_logger_set_file(mget_get_logger(MGET_LOGGER_DEBUG), va_arg(args, const char *));
			break;
		case MGET_ERROR_STREAM:
			mget_logger_set_stream(mget_get_logger(MGET_LOGGER_ERROR), va_arg(args, FILE *));
			break;
		case MGET_ERROR_FUNC:
			mget_logger_set_func(mget_get_logger(MGET_LOGGER_ERROR), va_arg(args, void (*)(const char *, size_t)));
			break;
		case MGET_ERROR_FILE:
			mget_logger_set_file(mget_get_logger(MGET_LOGGER_ERROR), va_arg(args, const char *));
			break;
		case MGET_INFO_STREAM:
			mget_logger_set_stream(mget_get_logger(MGET_LOGGER_INFO), va_arg(args, FILE *));
			break;
		case MGET_INFO_FUNC:
			mget_logger_set_func(mget_get_logger(MGET_LOGGER_INFO), va_arg(args, void (*)(const char *, size_t)));
			break;
		case MGET_INFO_FILE:
			mget_logger_set_file(mget_get_logger(MGET_LOGGER_INFO), va_arg(args, const char *));
			break;
		case MGET_DNS_CACHING:
			mget_tcp_set_dns_caching(va_arg(args, int));
			break;
		case MGET_COOKIE_SUFFIXES:
			mget_cookie_load_public_suffixes(va_arg(args, const char *));
			_config.cookies_enabled = 1;
			break;
		case MGET_COOKIES_ENABLED:
			_config.cookies_enabled = va_arg(args, int);
			break;
		case MGET_COOKIE_STORE:
			// load cookie-store
			_config.cookies_enabled = 1;
			_config.cookie_store = va_arg(args, const char *);
			break;
		case MGET_COOKIE_KEEPSESSIONCOOKIES:
			_config.keep_session_cookies = va_arg(args, int);
			break;
		case MGET_BIND_ADDRESS:
			mget_tcp_set_bind_address(va_arg(args, const char *));
			break;
		case MGET_NET_FAMILY_EXCLUSIVE:
			mget_tcp_set_family(va_arg(args, int));
			break;
		case MGET_NET_FAMILY_PREFERRED:
			mget_tcp_set_preferred_family(va_arg(args, int));
			break;
		default:
			pthread_mutex_unlock(&_mutex);
			mget_error_printf(_("%s: Unknown option %d"), __func__, key);
			return;
		}
	}
	va_end(args);

	if (_config.cookies_enabled && _config.cookie_store)
		mget_cookie_load(_config.cookie_store, _config.keep_session_cookies);

	pthread_mutex_unlock(&_mutex);
}

void mget_global_deinit(void)
{
	pthread_mutex_lock(&_mutex);

	if (_init == 1) {
		// free resources here
		mget_cookie_free_public_suffixes();
		if (_config.cookies_enabled && _config.cookie_store)
			mget_cookie_save(_config.cookie_store, _config.keep_session_cookies);
		mget_cookie_free_cookies();
		mget_tcp_set_bind_address(NULL);
		mget_tcp_set_dns_caching(0);
	}

	if (_init > 0) _init--;

	pthread_mutex_unlock(&_mutex);
}

int mget_global_get_int(int key)
{
	switch (key) {
	case MGET_DNS_CACHING:
		return mget_tcp_get_dns_caching();
		break;
	case MGET_COOKIES_ENABLED:
		return _config.cookies_enabled;
		break;
	case MGET_COOKIE_KEEPSESSIONCOOKIES:
		return _config.keep_session_cookies;
		break;
	case MGET_NET_FAMILY_EXCLUSIVE:
		return mget_tcp_get_family();
		break;
	case MGET_NET_FAMILY_PREFERRED:
		return mget_tcp_get_preferred_family();
		break;
	default:
		mget_error_printf(_("%s: Unknown option %d"), __func__, key);
		return 0;
	}
}

const void *mget_global_get_ptr(int key)
{
	switch (key) {
	case MGET_DEBUG_STREAM:
		return mget_logger_get_stream(mget_get_logger(MGET_LOGGER_DEBUG));
	case MGET_DEBUG_FUNC:
		return (void *)mget_logger_get_func(mget_get_logger(MGET_LOGGER_DEBUG));
	case MGET_DEBUG_FILE:
		return mget_logger_get_file(mget_get_logger(MGET_LOGGER_DEBUG));
	case MGET_ERROR_STREAM:
		return mget_logger_get_stream(mget_get_logger(MGET_LOGGER_ERROR));
	case MGET_ERROR_FUNC:
		return (void *)mget_logger_get_func(mget_get_logger(MGET_LOGGER_ERROR));
	case MGET_ERROR_FILE:
		return mget_logger_get_file(mget_get_logger(MGET_LOGGER_ERROR));
	case MGET_INFO_STREAM:
		return mget_logger_get_stream(mget_get_logger(MGET_LOGGER_INFO));
	case MGET_INFO_FUNC:
		return (void *)mget_logger_get_func(mget_get_logger(MGET_LOGGER_INFO));
	case MGET_INFO_FILE:
		return mget_logger_get_file(mget_get_logger(MGET_LOGGER_INFO));
//	case MGET_COOKIE_SUFFIXES:
//		mget_cookie_load_public_suffixes(va_arg(args, const char *));
//		break;
	case MGET_COOKIE_STORE:
		return _config.cookie_store;
		break;
	default:
		mget_error_printf(_("%s: Unknown option %d"), __func__, key);
		return NULL;
	}
}

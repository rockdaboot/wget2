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
 * Header file for logging routines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_LOG_H
#define _MGET_LOG_H

#include <stdarg.h>

#include "mget.h"

void
	err_printf(const char *fmt, ...) PRINTF_FORMAT(1,2),
	err_printf_exit(const char *fmt, ...) PRINTF_FORMAT(1,2) NORETURN,
	info_printf(const char *fmt, ...) PRINTF_FORMAT(1,2),
	log_write(const char *buf, int len),
	log_printf(const char *fmt, ...) PRINTF_FORMAT(1,2),
	log_printf_exit(const char *fmt, ...) PRINTF_FORMAT(1,2) NORETURN,
	log_vprintf(const char *fmt, va_list args) PRINTF_FORMAT(1,0);

#endif /* _MGET_LOG_H */

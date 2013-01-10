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

// use the helper routines provided by libmget
#define info_printf mget_info_printf
#define error_printf  mget_error_printf
#define error_printf_exit  mget_error_printf_exit
#define debug_printf mget_debug_printf
#define debug_write mget_debug_write

void
	log_init(void);

#endif /* _MGET_LOG_H */

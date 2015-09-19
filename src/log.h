/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Header file for logging routines
 *
 * Changelog
 * 27.04.2012  Tim Ruehsen  created
 *
 */

#ifndef _WGET_LOG_H
#define _WGET_LOG_H

#include <stdarg.h>

// use the helper routines provided by libwget
#define info_printf wget_info_printf
#define error_printf  wget_error_printf
#define error_printf_exit  wget_error_printf_exit
#define debug_printf wget_debug_printf
#define debug_write wget_debug_write

void
	log_init(void);

#endif /* _WGET_LOG_H */

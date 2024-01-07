/*
 * Copyright (c) 2014 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file for progress bar routines
 *
 * Changelog
 * 11.09.2014  Tim Ruehsen  created
 *
 */

#ifndef SRC_WGET_BAR_H
#define SRC_WGET_BAR_H

#define PROGRESS_TYPE_NONE  0
#define PROGRESS_TYPE_BAR   1

bool bar_init(void);
void bar_deinit(void);
void bar_print(int slot, const char *s) WGET_GCC_NONNULL_ALL;
void bar_printf(int slot, const char *fmt, ...) WGET_GCC_PRINTF_FORMAT(2,3) WGET_GCC_NONNULL_ALL;
void bar_vprintf(int slot, const char *fmt, va_list args) WGET_GCC_PRINTF_FORMAT(2,0) WGET_GCC_NONNULL_ALL;
void bar_slot_begin(int slot, const char *filename, int new_file, ssize_t filesize);
void bar_set_downloaded(int slot, size_t nbytes);
void bar_slot_deregister(int slot);
void bar_update_slots(int nslots);

/*
ssize_t
	wget_bar_vprintf(wget_bar *bar, int slot, const char *fmt, va_list args) WGET_GCC_PRINTF_FORMAT(3,0) WGET_GCC_NONNULL_ALL;
ssize_t
	wget_bar_printf(wget_bar *bar, int slot, const char *fmt, ...) WGET_GCC_PRINTF_FORMAT(3,4) WGET_GCC_NONNULL_ALL;
void
	wget_bar_print(wget_bar *bar, int slot, const char *s) WGET_GCC_NONNULL_ALL;
*/
#endif /* SRC_WGET_BAR_H */

/*
 * Copyright(c) 2014 Tim Ruehsen
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
 * Header file for job routines
 *
 * Changelog
 * 11.09.2014  Tim Ruehsen  created
 *
 */

#ifndef _WGET_BAR_H
#define _WGET_BAR_H

void
	bar_init(void),
	bar_deinit(void),
	bar_print(int slotpos, const char *s) G_GNUC_WGET_NONNULL_ALL,
	bar_printf(int slotpos, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(2,3) G_GNUC_WGET_NONNULL_ALL,
	bar_vprintf(int slotpos, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(2,0) G_GNUC_WGET_NONNULL_ALL,
	bar_update(int slotpos, int max, int cur);

/*
ssize_t
	wget_bar_vprintf(wget_bar_t *bar, int slotpos, const char *fmt, va_list args) G_GNUC_WGET_PRINTF_FORMAT(3,0) G_GNUC_WGET_NONNULL_ALL;
ssize_t
	wget_bar_printf(wget_bar_t *bar, int slotpos, const char *fmt, ...) G_GNUC_WGET_PRINTF_FORMAT(3,4) G_GNUC_WGET_NONNULL_ALL;
void
	wget_bar_print(wget_bar_t *bar, int slotpos, const char *s)G_GNUC_WGET_NONNULL_ALL;
*/
#endif /* _WGET_BAR_H */

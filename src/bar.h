/*
 * Copyright(c) 2014 Tim Ruehsen
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
 * Header file for job routines
 *
 * Changelog
 * 11.09.2014  Tim Ruehsen  created
 *
 */

#ifndef _MGET_BAR_H
#define _MGET_BAR_H

void
	bar_init(void),
	bar_deinit(void),
	bar_print(int slotpos, const char *s) G_GNUC_MGET_NONNULL_ALL,
	bar_printf(int slotpos, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(2,3) G_GNUC_MGET_NONNULL_ALL;
/*
ssize_t
	mget_bar_vprintf(mget_bar_t *bar, int slotpos, const char *fmt, va_list args) G_GNUC_MGET_PRINTF_FORMAT(3,0) G_GNUC_MGET_NONNULL_ALL;
ssize_t
	mget_bar_printf(mget_bar_t *bar, int slotpos, const char *fmt, ...) G_GNUC_MGET_PRINTF_FORMAT(3,4) G_GNUC_MGET_NONNULL_ALL;
void
	mget_bar_print(mget_bar_t *bar, int slotpos, const char *s)G_GNUC_MGET_NONNULL_ALL;
*/
#endif /* _MGET_BAR_H */

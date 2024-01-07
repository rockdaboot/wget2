/*
 * Copyright (c) 2016-2024 Free Software Foundation, Inc.
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
 * Console functions
 *
 */

#include <config.h>

#include <wget.h>
#include "private.h"

#ifdef _WIN32
#include <windows.h>
CONSOLE_SCREEN_BUFFER_INFO g_console_info;
HANDLE                     g_stdout_hnd = INVALID_HANDLE_VALUE;
CRITICAL_SECTION           g_trace_crit;
#endif

/**
 * \file
 * \brief Console functions
 * \defgroup libwget-console Console functions
 * @{
 *
 * Routines to address console controls like cursor positioning, fg+bg colors, ...
 */

static void reset_color(void)
{
#ifdef _WIN32
	fflush(stdout);

	if (g_stdout_hnd != INVALID_HANDLE_VALUE) {
		SetConsoleTextAttribute(g_stdout_hnd, g_console_info.wAttributes);
		g_stdout_hnd = INVALID_HANDLE_VALUE;
	}
#else
	if (isatty(fileno(stdout)))
		fputs("\033[m", stdout);
	fflush(stdout);
#endif
}

/**
 * \param[in] colorid Number of foreground/text color to set
 *
 * Sets the console foreground (text) color.
 */
#ifdef _WIN32
void wget_console_set_fg_color(wget_console_color colorid)
{
	if (g_stdout_hnd != INVALID_HANDLE_VALUE) {
		static short color[] = {
			[WGET_CONSOLE_COLOR_WHITE] = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED,
			[WGET_CONSOLE_COLOR_BLUE] = FOREGROUND_BLUE,
			[WGET_CONSOLE_COLOR_GREEN] = FOREGROUND_GREEN,
			[WGET_CONSOLE_COLOR_RED] = FOREGROUND_RED,
			[WGET_CONSOLE_COLOR_MAGENTA] = FOREGROUND_RED | FOREGROUND_BLUE
		};

		fflush (stdout);

		if (colorid == WGET_CONSOLE_COLOR_RESET)
			SetConsoleTextAttribute (g_stdout_hnd, g_console_info.wAttributes);
		else if (colorid < countof(color)) {
			WORD attr = (g_console_info.wAttributes & ~7) | color[colorid];

			SetConsoleTextAttribute (g_stdout_hnd, attr | FOREGROUND_INTENSITY);
		}
	}
}
#else
void wget_console_set_fg_color(WGET_GCC_UNUSED wget_console_color colorid)
{
}
#endif

/**
 * Resets the console foreground (text) color.
 */
void wget_console_reset_fg_color(void)
{
	wget_console_set_fg_color(WGET_CONSOLE_COLOR_RESET);
}
#ifdef _WIN32
static DWORD SetupConsoleHandle(BOOL is_input, HANDLE handle) {
	DWORD mode = 0;
	if (handle == INVALID_HANDLE_VALUE)
		return mode;
	if (!GetConsoleMode(handle, &mode))
		return mode;
	DWORD orig = mode;
	if (is_input)
		mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
	else
		mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;

	SetConsoleMode(handle, mode);
	return orig;
}
#endif
/**
 * \return 0 on success, or -1 on error
 *
 * Initializes the console.
 */
int wget_console_init(void)
{
#ifdef _WIN32
	static int win_init;

	if (win_init)
		return 0;

	g_stdout_hnd = GetStdHandle(STD_OUTPUT_HANDLE);
	if (g_stdout_hnd != INVALID_HANDLE_VALUE) {
		GetConsoleScreenBufferInfo(g_stdout_hnd, &g_console_info);

		if (GetFileType(g_stdout_hnd) != FILE_TYPE_CHAR) /* The console is redirected */
			g_stdout_hnd = INVALID_HANDLE_VALUE;
	}
	SetupConsoleHandle(true, GetStdHandle(STD_INPUT_HANDLE));
	SetupConsoleHandle(false, GetStdHandle(STD_OUTPUT_HANDLE));
	win_init = 1;
#endif

	atexit(reset_color);

	return 0;
}

/**
 * \return 0 on success, or -1 on error
 *
 * Deinitializes the console.
 */
int wget_console_deinit(void)
{
	reset_color();

	return 0;
}

/**@}*/

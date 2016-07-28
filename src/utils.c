/*
 * Copyright(c) 2014 Tim Ruehsen
 * Copyright(c) 2015-2016 Free Software Foundation, Inc.
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
 * Some utlity methods for use within LibWget
 *
 * Changelog
 * 23/07/2016	Darshit Shah	created
 */

#include "utils.h"

#include <config.h>
#include <libwget.h>

#ifdef HAVE_IOCTL
#	include <sys/ioctl.h>
#	include <termios.h>
#endif

/* Determine the width of the terminal we're running on.  If that's
   not possible, return 0.  */
int
determine_screen_width (void)
{
  /* If there's a way to get the terminal size using POSIX
     tcgetattr(), somebody please tell me.  */
  int fd;
  struct winsize wsz;

  fd = fileno (stderr);

#ifdef HAVE_IOCTL
  if (ioctl (fd, TIOCGWINSZ, &wsz) < 0)
    return 0;                   /* most likely ENOTTY */
#else
  return 0;
#endif

  return wsz.ws_col;
}

/*
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
 * Header file for xattr routines
 */

#ifndef SRC_WGET_XATTR_H
#define SRC_WGET_XATTR_H

#include <stdio.h>
#include <time.h>

#if defined __linux
/* libc on Linux has fsetxattr (5 arguments). */
/* libc on Linux has fgetxattr (4 arguments). */
#  include <sys/xattr.h>
#  define USE_XATTR
#elif defined __APPLE__
/* libc on OS/X has fsetxattr (6 arguments). */
/* libc on OS/X has fgetxattr (6 arguments). */
#  include <sys/xattr.h>
#  define fsetxattr(file, name, buffer, size, flags) \
          fsetxattr((file), (name), (buffer), (size), 0, (flags))
#  define fgetxattr(file, name, buffer, size) \
          fgetxattr((file), (name), (buffer), (size), 0, 0)
#  define USE_XATTR
#elif defined __FreeBSD_version && (__FreeBSD_version > 500000)
/* FreeBSD */
#  include <sys/types.h>
#  include <sys/extattr.h>
#  define fsetxattr(file, name, buffer, size, flags) \
          extattr_set_fd((file), EXTATTR_NAMESPACE_USER, (name), (buffer), (size))
#  define fgetxattr(file, name, buffer, size) \
          extattr_set_fd((file), EXTATTR_NAMESPACE_USER, (name), (buffer), (size))
#  define USE_XATTR
#endif

#endif /* SRC_WGET_XATTR_H */

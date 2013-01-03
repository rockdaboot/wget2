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
 * Header file for hash functions
 *
 * Changelog
 * 29.07.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_HASH_H
#define _MGET_HASH_H

int
   hash_file_fd(const char *type, int fd, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length) NONNULL_ALL,
   hash_file_offset(const char *type, const char *fname, char *digest_hex, size_t digest_hex_size, off_t offset, off_t length) NONNULL_ALL,
   hash_file(const char *type, const char *fname, char *digest_hex, size_t digest_hex_size) NONNULL_ALL;


#endif /* _MGET_HASH_H */

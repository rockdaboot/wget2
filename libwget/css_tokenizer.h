/*
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
 * Changelog
 * 16.07.2012  Tim Ruehsen  created
 *
 */

#ifndef LIBWGET_CSS_TOKENIZER_H
# define LIBWGET_CSS_TOKENIZER_H

enum {
  CSSEOF = 0,
  S = 1,
  CDO = 2,
  CDC = 3,
  INCLUDES = 4,
  DASHMATCH = 5,
  STRING = 6,
  BAD_STRING = 7,
  IDENT = 8,
  HASH = 9,
  IMPORT_SYM = 10,
  PAGE_SYM = 11,
  MEDIA_SYM = 12,
  CHARSET_SYM = 13,
  IMPORTANT_SYM = 14,
  EMS = 15,
  EXS = 16,
  LENGTH = 17,
  ANGLE = 18,
  TIME = 19,
  FREQ = 20,
  DIMENSION = 21,
  PERCENTAGE = 22,
  NUMBER = 23,
  URI = 24,
  BAD_URI = 25,
  FUNCTION = 26,
  COMMENT = 27
};

# define YY_FATAL_ERROR(msg) wget_error_printf_exit(msg)

#endif /* LIBWGET_CSS_TOKENIZER_H */

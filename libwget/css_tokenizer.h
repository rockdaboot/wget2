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
 * along with libwget.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Changelog
 * 16.07.2012  Tim Ruehsen  created
 * 
 */

#ifndef CSS_TOKENIZER_H
#define CSS_TOKENIZER_H

enum {
  CSSEOF,
  S,
  CDO,
  CDC,
  INCLUDES,
  DASHMATCH,
  STRING,
  BAD_STRING,
  IDENT,
  HASH,
  IMPORT_SYM,
  PAGE_SYM,
  MEDIA_SYM,
  CHARSET_SYM,
  IMPORTANT_SYM,
  EMS,
  EXS,
  LENGTH,
  ANGLE,
  TIME,
  FREQ,
  DIMENSION,
  PERCENTAGE,
  NUMBER,
  URI,
  BAD_URI,
  FUNCTION,
  COMMENT
};

#define YY_FATAL_ERROR(msg) wget_error_printf_exit(msg)

#endif /* CSS_TOKENIZER_H */

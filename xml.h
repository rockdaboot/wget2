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
 * Header file for xml parsing routines
 *
 * Changelog
 * 22.06.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_XML_H
#define _MGET_XML_H

#include "mget.h"

#define XML_FLG_BEGIN      (1<<0) // <
#define XML_FLG_CLOSE      (1<<1) // >
#define XML_FLG_END        (1<<2) // </elem>
#define XML_FLG_ATTRIBUTE  (1<<3) // attr="value"
#define XML_FLG_CONTENT    (1<<4)
#define XML_FLG_COMMENT    (1<<5) // <!-- ... -->
//#define XML_FLG_CDATA      (1<<6) // <![CDATA[...]]>, now same handling as 'special'
#define XML_FLG_PROCESSING (1<<7) // e.g. <? ... ?>
#define XML_FLG_SPECIAL    (1<<8) // e.g. <!DOCTYPE ...>

#define XML_HINT_REMOVE_EMPTY_CONTENT (1<<0) // merge spaces, remove empty content
#define XML_HINT_HTML                 (1<<1) // parse HTML instead of XML

#define HTML_HINT_REMOVE_EMPTY_CONTENT XML_HINT_REMOVE_EMPTY_CONTENT

void
	xml_parse_buffer(
		const char *buf,
		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) NONNULL(1),
	xml_parse_file(
		const char *fname,
		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *val),
		void *user_ctx,
		int hints) NONNULL(1),
	html_parse_buffer(
		const char *buf,
		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) NONNULL(1),
	html_parse_file(
		const char *fname,
		void(*callback)(void *user_ctx, int flags, const char *dir, const char *attr, const char *tok),
		void *user_ctx,
		int hints) NONNULL(1);

#endif /* _MGET_XML_H */

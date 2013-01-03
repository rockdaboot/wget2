/*
 * (c)2012 Tim Ruehsen
 *
 * Header file for xml parsing routines
 *
 * Source Code License
 *   CC0 1.0 Universal (CC0 1.0) Public Domain Dedication
 *   http://creativecommons.org/publicdomain/zero/1.0/legalcode
 *
 * Changelog
 * 22.06.2012  Tim Ruehsen  created
 *
 */

#ifndef _MGET_CSS_H
#define _MGET_CSS_H

#include <stddef.h>

void
	css_parse_buffer(
		const char *buf,
		void(*callback_uri)(void *user_ctx, const char *url, size_t len),
		void(*callback_encoding)(void *user_ctx, const char *url, size_t len),
		void *user_ctx),
	css_parse_file(
		const char *fname,
		void(*callback_uri)(void *user_ctx, const char *url, size_t len),
		void(*callback_encoding)(void *user_ctx, const char *url, size_t len),
		void *user_ctx);

#endif /* _MGET_CSS_H */

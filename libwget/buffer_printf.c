/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * Memory buffer printf routines
 *
 * Changelog
 * 24.09.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <c-ctype.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Buffer management functions
 * \defgroup libwget-buffer Buffer management functions
 * @{
 */

/* \cond _hide_internal_symbols */
#define FLAG_ZERO_PADDED   1U
#define FLAG_LEFT_ADJUST   2U
#define FLAG_ALTERNATE     4U
#define FLAG_SIGNED        8U
#define FLAG_DECIMAL      16U
#define FLAG_OCTAL        32U
#define FLAG_HEXLO        64U
#define FLAG_HEXUP       128U
/* \endcond */

static void copy_string(wget_buffer *buf, unsigned int flags, int field_width, int precision, const char *arg)
{
	size_t length;

	if (!arg) {
		wget_buffer_strcat(buf, "(null)");
		return;
	}

	if (precision >= 0) {
		length = strnlen(arg, precision);
	} else {
		length = strlen(arg);
	}

	// debug_printf("flags=0x%02x field_width=%d precision=%d length=%zu arg='%s'\n",
	//	flags,field_width,precision,length,arg);

	if (field_width) {
		if ((unsigned)field_width > length) {
			if (flags & FLAG_LEFT_ADJUST) {
				wget_buffer_memcat(buf, arg, length);
				wget_buffer_memset_append(buf, ' ', field_width - length);
			} else {
				wget_buffer_memset_append(buf, ' ', field_width - length);
				wget_buffer_memcat(buf, arg, length);
			}
		} else {
			wget_buffer_memcat(buf, arg, length);
		}
	} else {
		wget_buffer_memcat(buf, arg, length);
	}
}

static void convert_dec_fast(wget_buffer *buf, int arg)
{
	char str[32]; // long enough to hold decimal long long
	char *dst = str + sizeof(str) - 1;
	int minus;

	if (arg < 0) {
		minus = 1;
		arg = -arg;
	} else
		minus = 0;

	while (arg >= 10) {
		*dst-- = (arg % 10) + '0';
		arg /= 10;
	}
	*dst-- = (arg % 10) + '0';

	if (minus)
		*dst-- = '-';

	wget_buffer_memcat(buf, dst + 1, sizeof(str) - (dst - str) - 1);
}

static void convert_dec(wget_buffer *buf, unsigned int flags, int field_width, int precision, long long arg)
{
	unsigned long long argu = (unsigned long long) arg;
	char str[32], minus = 0; // long enough to hold decimal long long
	char *dst = str + sizeof(str) - 1;
	unsigned char c;
	size_t length;

	// info_printf("arg1 = %lld %lld\n",arg,-arg);

	if (flags & FLAG_DECIMAL) {
		if (flags & FLAG_SIGNED && arg < 0) {
			minus = 1;
			argu = -arg;
		}

		while (argu) {
			*dst-- = argu % 10 + '0';
			argu /= 10;
		}
	} else if (flags & FLAG_HEXLO) {
		while (argu) {
			// slightly faster than having a HEX[] lookup table
			*dst-- = (c = (argu & 0xf)) >= 10 ? c + 'a' - 10 : c + '0';
			argu >>= 4;
		}
	} else if (flags & FLAG_HEXUP) {
		while (argu) {
			// slightly faster than having a HEX[] lookup table
			*dst-- = (c = (argu & 0xf)) >= 10 ? c + 'A' - 10 : c + '0';
			argu >>= 4;
		}
	} else if (flags & FLAG_OCTAL) {
		while (argu) {
			*dst-- = (argu & 0x07) + '0';
			argu >>= 3;
		}
	}

	// info_printf("arg2 = %lld\n",arg);


	dst++;

	length =  sizeof(str) - (dst - str);

	if (precision < 0) {
		precision = 1;
	} else {
		flags &= ~FLAG_ZERO_PADDED;
	}

	// info_printf("flags=0x%02x field_width=%d precision=%d length=%zd dst='%.*s'\n",
	//	flags,field_width,precision,length,length,dst);

	if (field_width) {
		if ((unsigned)field_width > length + minus) {
			if (flags & FLAG_LEFT_ADJUST) {
				if (minus)
					wget_buffer_memset_append(buf, '-', 1);

				if (length < (unsigned)precision) {
					wget_buffer_memset_append(buf, '0', precision - length);
					wget_buffer_memcat(buf, dst, length);
					if (field_width > precision + minus)
						wget_buffer_memset_append(buf, ' ', field_width - precision - minus);
				} else {
						wget_buffer_memcat(buf, dst, length);
						wget_buffer_memset_append(buf, ' ', field_width - length - minus);
				}
			} else {
				if (length < (unsigned)precision) {
					if (field_width > precision + minus) {
						if (flags & FLAG_ZERO_PADDED) {
							if (minus)
								wget_buffer_memset_append(buf, '-', 1);
							wget_buffer_memset_append(buf, '0', field_width - precision - minus);
						} else {
							wget_buffer_memset_append(buf, ' ', field_width - precision - minus);
							if (minus)
								wget_buffer_memset_append(buf, '-', 1);
						}
					} else {
						if (minus)
							wget_buffer_memset_append(buf, '-', 1);
					}
					wget_buffer_memset_append(buf, '0', precision - length);
				} else {
					if (flags & FLAG_ZERO_PADDED) {
						if (minus)
							wget_buffer_memset_append(buf, '-', 1);
						wget_buffer_memset_append(buf, '0', field_width - length - minus);
					} else {
						wget_buffer_memset_append(buf, ' ', field_width - length - minus);
						if (minus)
							wget_buffer_memset_append(buf, '-', 1);
					}
				}
				wget_buffer_memcat(buf, dst, length);
			}
		} else {
			if (minus)
				wget_buffer_memset_append(buf, '-', 1);
			if (length < (unsigned)precision)
				wget_buffer_memset_append(buf, '0', precision - length);
			wget_buffer_memcat(buf, dst, length);
		}
	} else {
		if (minus)
			wget_buffer_memset_append(buf, '-', 1);

		if (length < (unsigned)precision)
			wget_buffer_memset_append(buf, '0', precision - length);

		wget_buffer_memcat(buf, dst, length);
	}
}

static void convert_pointer(wget_buffer *buf, void *pointer)
{
	static const char HEX[16] = "0123456789abcdef";
	char str[32]; // long enough to hold hexadecimal pointer
	char *dst;
	int length;
	size_t arg;

	if (!pointer) {
		wget_buffer_memcat(buf, "0x0", 3);
		return;
	} else {
		wget_buffer_memcat(buf, "0x", 2);
	}

	// convert to a size_t (covers full address room) tp allow integer arithmetic
	arg = (size_t)pointer;

	length = 0;
	dst = str + sizeof(str);
	*--dst = 0;
	do {
		*--dst = HEX[arg&0xF];
		arg >>= 4;
		length++;
	} while (arg);

	wget_buffer_memcat(buf, dst, length);
}

static const char *read_precision(const char *p, int *out, bool precision_is_external)
{
	int precision;

	if (precision_is_external) {
		precision = *out;
		if (precision < 0 )
			precision = 0;
		p++;
	} else if (c_isdigit(*p)) {
		precision = 0;
		do {
			precision = precision * 10 + (*p - '0');
		} while (c_isdigit(*++p));
	} else {
		precision = -1;
	}

	*out = precision;
	return p;
}

static const char *read_flag_chars(const char *p, unsigned int *out)
{
	unsigned int flags;

	for (flags = 0; *p; p++) {
		if (*p == '0')
			flags |= FLAG_ZERO_PADDED;
		else if (*p == '-')
			flags |= FLAG_LEFT_ADJUST;
		else if (*p == '#')
			flags |= FLAG_ALTERNATE;
		else
			break;
	}

	*out = flags;
	return p;
}

static const char *read_field_width(const char *p, int *out, unsigned int *flags, bool width_is_external)
{
	int field_width;

	if (width_is_external) {
		field_width = *out;

		if (field_width < 0) {
			*flags |= FLAG_LEFT_ADJUST;
			field_width = -field_width;
		}

		p++;
	} else {
		for (field_width = 0; c_isdigit(*p); p++)
			field_width = field_width * 10 + (*p - '0');
	}

	*out = field_width;
	return p;
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] fmt A `printf(3)`-like format string
 * \param[in] args A `va_list` with the format string placeholders' values
 * \return Length of the buffer after appending the formatted string
 *
 * Formats the string \p fmt (with `printf(3)`-like args) and appends the result to the end
 * of the buffer \p buf (using wget_buffer_memcat()).
 *
 * For more information, see `vprintf(3)`.
 */
size_t wget_buffer_vprintf_append(wget_buffer *buf, const char *fmt, va_list args)
{
	const char *p = fmt, *begin;
	int field_width, precision;
	unsigned int flags;
	long long arg;
	unsigned long long argu;

	if (!p)
		return 0;

	for (;*p;) {

		/*
		 * Collect plain char sequence.
		 * Walk the string until we find a '%' character.
		 */
		for (begin = p; *p && *p != '%'; p++);
		if (p != begin)
			wget_buffer_memcat(buf, begin, p - begin);

		if (!*p)
			break;

		/* Shortcut to %s and %p, handle %% */
		if (*++p == 's') {
			const char *s = va_arg(args, const char *);
			wget_buffer_strcat(buf, s ? s : "(null)");
			p++;
			continue;
		} else if (*p == 'd') {
			convert_dec_fast(buf, va_arg(args, int));
			p++;
			continue;
		} else if (*p == 'c') {
			char c = (char ) va_arg(args, int);
			wget_buffer_memcat(buf, &c, 1);
			p++;
			continue;
		} else if (*p == 'p') {
			convert_pointer(buf, va_arg(args, void *));
			p++;
			continue;
		} else if (*p == '%') {
			wget_buffer_memset_append(buf, '%', 1);
			p++;
			continue;
		}

		/* Read the flag chars (optional, simplified) */
		p = read_flag_chars(p, &flags);

		/*
		 * Read field width (optional).
		 * If '*', then the field width is given as an additional argument,
		 * which precedes the argument to be formatted.
		 */
		if (*p == '*') {
			field_width = va_arg(args, int);
			p = read_field_width(p, &field_width, &flags, 1);
		} else {
			p = read_field_width(p, &field_width, &flags, 0);
		}

		/*
		 * Read precision (optional).
		 * If '*', the precision is given as an additional argument,
		 * just as the case for the field width.
		 */
		if (*p == '.') {
			if (*++p == '*') {
				precision = va_arg(args, int);
				p = read_precision(p, &precision, 1);
			} else {
				p = read_precision(p, &precision, 0);
			}
		} else
			precision = -1;

		/* Read length modifier (optional) */
		switch (*p) {
		case 'z':
			arg = va_arg(args, ssize_t);
			argu = (size_t)arg;
			p++;
			break;

		case 'l':
			if (p[1] == 'l') {
				p += 2;
				arg = va_arg(args, long long);
				argu = (unsigned long long)arg;
			} else {
				p++;
				arg = (long)va_arg(args, long);
				argu = (unsigned long)arg;
			}
			break;

		case 'L':
			p++;
			arg = va_arg(args, long long);
			argu = (unsigned long long)arg;
			break;

		case 'h':
			if (p[1] == 'h') {
				p += 2;
				arg = (signed char) va_arg(args, int);
				argu = (unsigned char) arg;
			} else {
				p++;
				arg = (short) va_arg(args, int);
				argu = (unsigned short) arg;
			}
			break;

		case 's':
			p++;
			copy_string(buf, flags, field_width, precision, va_arg(args, const char *));
			continue;

		case 'c':
		{
			char c[2] = { (char) va_arg(args, int), 0 };
			p++;
			copy_string(buf, flags, field_width, precision, c);
			continue;
		}

		case 'p': // %p shortcut
			p++;
			convert_dec(buf, flags | FLAG_HEXLO | FLAG_ALTERNATE, field_width, precision, (long long)(ptrdiff_t)va_arg(args, void *));
			continue;

		default:
			arg = va_arg(args, int);
			argu = (unsigned int)arg;
		}

		if (*p == 'd' || *p == 'i') {
			convert_dec(buf, flags | FLAG_SIGNED | FLAG_DECIMAL, field_width, precision, arg);
		} else if (*p == 'u') {
			convert_dec(buf, flags | FLAG_DECIMAL, field_width, precision, (long long) argu);
		} else if (*p == 'x') {
			convert_dec(buf, flags | FLAG_HEXLO, field_width, precision, (long long) argu);
		} else if (*p == 'X') {
			convert_dec(buf, flags | FLAG_HEXUP, field_width, precision, (long long) argu);
		} else if (*p == 'o') {
			convert_dec(buf, flags | FLAG_OCTAL, field_width, precision, (long long) argu);
		} else {
			/*
			 * This is an unknown conversion specifier,
			 * so just put '%' and move on.
			 */
			wget_buffer_memset_append(buf, '%', 1);
			p = begin + 1;
			continue;
		}

		p++;
	}

	return buf->length;
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] fmt A `printf(3)`-like format string
 * \param[in] args A `va_list` with the format string placeholders' values
 * \return Length of the buffer after appending the formatted string
 *
 * Formats the string \p fmt (with `printf(3)`-like args) and overwrites the contents
 * of the buffer \p buf with that formatted string.
 *
 * This is equivalent to the following code:
 *
 *     buf->length = 0;
 *     wget_buffer_vprintf_append(buf, fmt, args);
 *
 * For more information, see `vprintf(3)`.
 */
size_t wget_buffer_vprintf(wget_buffer *buf, const char *fmt, va_list args)
{
	buf->length = 0;

	return wget_buffer_vprintf_append(buf, fmt, args);
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] fmt A `printf(3)`-like format string
 * \param[in] ... Variable arguments
 * \return Length of the buffer after appending the formatted string
 *
 * Formats the string \p fmt (with `printf(3)`-like args) and appends the result to the end
 * of the buffer \p buf (using wget_buffer_memcat()).
 *
 * This function is equivalent to wget_buffer_vprintf_append(), except in that it uses
 * a variable number of arguments rather than a `va_list`.
 *
 * For more information, see `printf(3)`.
 */
size_t wget_buffer_printf_append(wget_buffer *buf, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	wget_buffer_vprintf_append(buf, fmt, args);
	va_end(args);

	return buf->length;
}

/**
 * \param[in] buf A buffer, created with wget_buffer_init() or wget_buffer_alloc()
 * \param[in] fmt A `printf(3)`-like format string
 * \param[in] ... Variable arguments
 * \return Length of the buffer after appending the formatted string
 *
 * Formats the string \p fmt (with `printf(3)`-like args) and overwrites the contents
 * of the buffer \p buf with that formatted string.
 *
 * This function is equivalent to wget_buffer_vprintf(), except in that it uses
 * a variable number of arguments rather than a `va_list`.
 *
 * For more information, see `printf(3)`.
 */
size_t wget_buffer_printf(wget_buffer *buf, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	size_t len = wget_buffer_vprintf(buf, fmt, args);
	va_end(args);

	return len;
}
/** @} */

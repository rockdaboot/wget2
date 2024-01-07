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
 * a collection of utility routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <glob.h>

#include "c-ctype.h"
#include "c-strcase.h"

#if defined __clang__
  // silence warnings in gnulib code
  #pragma clang diagnostic ignored "-Wshorten-64-to-32"
#endif

#include "timespec.h" // gnulib gettime()

#ifdef HAVE_IOCTL
#	include <sys/ioctl.h>
#	include <termios.h>
#endif

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief General utility functions
 * \defgroup libwget-utils General utility functions
 * @{
 *
 * This is a collections of short routines that are used with libwget and/or Wget code.
 * They may be useful to other developers that is why they are exported.
 */

/**
 * \param[in] s1 String
 * \param[in] s2 String
 * \return
 * 0 if both \p s1 and \p s2 are NULL<br>
 * -1 if \p s1 is NULL and \p s2 is not NULL<br>
 * 1 if \p s1 is not NULL and \p s2 is NULL
 * else it returns strcmp(\p s1, \p s2)
 *
 * This functions compares \p s1 and \p s2 in the same way as strcmp() does,
 * except that it also handles NULL values.
 */
int wget_strcmp(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strcmp(s1, s2);
	}
}

/**
 * \param[in] s1 String
 * \param[in] s2 String
 * \return
 * 0 if both \p s1 and \p s2 are NULL<br>
 * -1 if \p s1 is NULL and \p s2 is not NULL<br>
 * 1 if \p s1 is not NULL and \p s2 is NULL
 * else it returns strcasecmp(\p s1, \p s2)
 *
 * This functions compares \p s1 and \p s2 in the same way as strcasecmp() does,
 * except that it also handles NULL values.
 */
int wget_strcasecmp(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strcasecmp(s1, s2);
	}
}

/**
 * \param[in] s1 String
 * \param[in] s2 String
 * \return
 * 0 if both \p s1 and \p s2 are the same disregarding case for ASCII letters a-z<br>
 * 0 if both \p s1 and \p s2 are NULL<br>
 * <0 if \p s1 is NULL and \p s2 is not NULL or \p s1 is smaller than \p s2<br>
 * >0 if \p s2 is NULL and \p s1 is not NULL or \p s1 is greater than \p s2.
 *
 * This functions compares \p s1 and \p s2 as ASCII strings, case insensitive.
 * It also accepts NULL values.
 */
int wget_strcasecmp_ascii(const char *s1, const char *s2)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return c_strcasecmp(s1, s2);
	}
}

/**
 * \param[in] s1 String
 * \param[in] s2 String
 * \param[in] n Max. number of chars to compare
 * \return
 * 0 if both \p s1 and \p s2 are the same disregarding case for ASCII letters a-z<br>
 * 0 if both \p s1 and \p s2 are NULL<br>
 * <0 if \p s1 is NULL and \p s2 is not NULL or \p s1 is smaller than \p s2<br>
 * >0 if \p s2 is NULL and \p s1 is not NULL or \p s1 is greater than \p s2.
 *
 * This functions compares \p s1 and \p s2 as ASCII strings, case insensitive, up to a max number of \p n chars.
 * It also accepts NULL values.
 */
int wget_strncasecmp_ascii(const char *s1, const char *s2, size_t n)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return c_strncasecmp(s1, s2, n);
	}
}

/**
 * @param[in,out] s String to convert
 * \return Value of s
 *
 * Converts ASCII string \p s to lowercase in place.
 */
char *wget_strtolower(char *s)
{
	if (s) {
		for (char *d = s; *d; d++) {
			if (c_isupper(*d))
				*d = (char) c_tolower(*d);
		}
	}

	return s;
}

/**
 * \param[in] s1 String
 * \param[in] s2 String
 * \param[in] n Max. number of chars to compare
 * \return
 * 0 if both \p s1 and \p s2 are the same or if both \p s1 and \p s2 are NULL<br>
 * <0 if \p s1 is NULL and \p s2 is not NULL or \p s1 is smaller than \p s2<br>
 * >0 if \p s2 is NULL and \p s1 is not NULL or \p s1 is greater than \p s2.
 *
 * This functions compares \p s1 and \p s2 in the same way as strncmp() does,
 * except that it also handles NULL values.
 */
int wget_strncmp(const char *s1, const char *s2, size_t n)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strncmp(s1, s2, n);
	}
}

/**
 * \param[in] s1 String
 * \param[in] s2 String
 * \param[in] n Max. number of chars to compare
 * \return
 * 0 if both \p s1 and \p s2 are the same disregarding case or if both \p s1 and \p s2 are NULL<br>
 * <0 if \p s1 is NULL and \p s2 is not NULL or \p s1 is smaller than \p s2<br>
 * >0 if \p s2 is NULL and \p s1 is not NULL or \p s1 is greater than \p s2.
 *
 * This functions compares \p s1 and \p s2 in the same way as strncasecmp() does,
 * except that it also handles NULL values.
 */
int wget_strncasecmp(const char *s1, const char *s2, size_t n)
{
	if (!s1) {
		if (!s2)
			return 0;
		else
			return -1;
	} else {
		if (!s2)
			return 1;
		else
			return strncasecmp(s1, s2, n);
	}
}

/**
 * \param[in] src Pointer to input buffer
 * \param[in] src_len Number of bytes to encode
 * \param[out] dst Buffer to hold the encoded string
 * \param[in] dst_size Size of \p dst in bytes
 *
 * Encodes a number of bytes into a lowercase hexadecimal C string.
 */
void wget_memtohex(const unsigned char *src, size_t src_len, char *dst, size_t dst_size)
{
	size_t it;
	int adjust = 0, c;

	if (dst_size == 0 || !dst || !src)
		return;

	if (src_len * 2 >= dst_size) {
		src_len = (dst_size - 1) / 2;
		adjust = 1;
	}

	for (it = 0; it < src_len; it++, src++) {
		*dst++ = (char) ((c = (*src >> 4)) >= 10 ? c + 'a' - 10 : c + '0');
		*dst++ = (char) ((c = (*src & 0xf)) >= 10 ? c + 'a' - 10 : c + '0');
	}
	if (adjust && (dst_size & 1) == 0)
		*dst++ = (char) ((c = (*src >> 4)) >= 10 ? c + 'a' - 10 : c + '0');

	*dst = 0;
}

/**
 * \param[in] ms Number of milliseconds to sleep
 *
 * Pause for \p ms milliseconds.
 */
void wget_millisleep(int ms)
{
	if (ms <= 0)
		return;

	nanosleep(&(struct timespec){ .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000 }, NULL);
}

/**
 * Return the current milliseconds since the epoch.
 */
long long wget_get_timemillis(void)
{
	struct timespec ts;

	gettime(&ts);

	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

WGET_GCC_CONST
static unsigned char unhex(unsigned char c)
{
	return c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10);
}

/**
 * \param[in,out] src String to unescape
 * \return
 * 0 if the string did not change<br>
 * 1 if unescaping took place
 *
 * Does an inline percent unescape.
 * Each occurrence of %xx (x = hex digit) will converted into it's byte representation.
 */
int wget_percent_unescape(char *src)
{
	int ret = 0;
	unsigned char *s = (unsigned char *)src; // just a helper to avoid casting a lot
	unsigned char *d = s;

	while (*s) {
		if (*s == '%') {
			if (c_isxdigit(s[1]) && c_isxdigit(s[2])) {
				*d++ = (unsigned char) (unhex(s[1]) << 4) | unhex(s[2]);
				s += 3;
				ret = 1;
				continue;
			}
		}

		*d++ = *s++;
	}
	*d = 0;

	return ret;
}

/**
 * \param[in] s String
 * \param[in] tail String
 * \return 1 if \p tail matches the end of \p s, 0 if not
 *
 * Checks if \p tail matches the end of the string \p s.
 */
int wget_match_tail(const char *s, const char *tail)
{
	size_t s_len, tail_len;

	if ((s_len = strlen(s)) < (tail_len = strlen(tail)))
		return 0;

	const char *p = s + (s_len - tail_len);

	return !strcmp(p, tail);
}

/**
 * \param[in] s String
 * \param[in] tail String
 * \return 1 if \p tail matches the end of \p s, 0 if not
 *
 * Checks if \p tail matches the end of the string \p s, disregarding the case, ASCII only.
 *
 */
int wget_match_tail_nocase(const char *s, const char *tail)
{
	size_t s_len, tail_len;

	if ((s_len = strlen(s)) < (tail_len = strlen(tail)))
		return 0;

	const char *p = s + (s_len - tail_len);

	return !wget_strcasecmp_ascii(p, tail);
}

/**
 * \param[in] str String to run glob() against
 * \param[in] n Length of string
 * \param[in] flags Flags to pass to glob()
 * \return Expanded string after running glob
 *
 * Finds a pathname by running glob(3) on the pattern in the first \p n bytes
 * of \p globstr.  Returns a newly allocated string with the first \p n
 * bytes replaced with the matching pattern obtained via glob(3) if one was
 * found. Otherwise it returns NULL.
 */
char *wget_strnglob(const char *str, size_t n, int flags)
{
	glob_t pglob;
	char *expanded_str = NULL;

	char *globstr = wget_strmemdup(str, n);

	if (!globstr)
		return NULL;

	if (glob(globstr, flags, NULL, &pglob) == 0) {
		if (pglob.gl_pathc > 0) {
			expanded_str = wget_aprintf("%s%s", pglob.gl_pathv[0], str+n);
		}
		globfree(&pglob);
	}

	xfree(globstr);
	return expanded_str;
}

/**
 * \param[in] buf Result buffer
 * \param[in] bufsize Size of /p buf
 * \param[in] n Number to convert
 * \return Pointer to printable representation of \p n
 *
 * Returns a human readable representation of \p n.
 * \p n, a byte quantity, is converted to a human-readable abbreviated
 * form a la sizes printed by `ls -lh'.  The result is written into the
 * provided buffer.
 *
 * Unlike `with_thousand_seps', this approximates to the nearest unit.
 * Quoting GNU libit: "Most people visually process strings of 3-4
 * digits effectively, but longer strings of digits are more prone to
 * misinterpretation.  Hence, converting to an abbreviated form
 * usually improves readability."
 *
 * This intentionally uses kilobyte (KB), megabyte (MB), etc. in their
 * original computer-related meaning of "powers of 1024".  We don't
 * use the "*bibyte" names invented in 1998, and seldom used in
 * practice.  Wikipedia's entry on "binary prefix" discusses this in
 * some detail.
 */
char *wget_human_readable(char *buf, size_t bufsize, uint64_t n)
{
	/* These suffixes are compatible with those of GNU `ls -lh'. */
	static const char powers[] = {
		'K', /* kilobyte,  2^10 bytes */
		'M', /* megabyte,  2^20 bytes */
		'G', /* gigabyte,  2^30 bytes */
		'T', /* terabyte,  2^40 bytes */
		'P', /* petabyte,  2^50 bytes */
		'E', /* exabyte,   2^60 bytes */
		'Z', /* zettabyte, 2^70 bytes */
		'Y', /* yottabyte, 2^80 bytes */
	};

	/* If the quantity is smaller than 1K, just print it. */
	if (n < 1024) {
		wget_snprintf(buf, bufsize, "%u ", (unsigned int) n);
		return buf;
	}

	/* Loop over powers, dividing N with 1024 in each iteration.  This
		works unchanged for all sizes of wgint, while still avoiding
		non-portable `long double' arithmetic.  */
	for (unsigned i = 0; i < countof(powers); i++) {
		/* At each iteration N is greater than the *subsequent* power.
			That way N/1024.0 produces a decimal number in the units of *this* power.  */
		if ((n / 1024) < 1024 || i == countof(powers) - 1) {
			double val = n / 1024.0;
			/* Print values smaller than the accuracy level (acc) with (decimal)
			 * decimal digits, and others without any decimals.  */
			if (val < 1000)
				wget_snprintf(buf, bufsize, "%d.%02d%c", (int) val , ((int) (val * 100)) % 100, powers[i]);
			else
				wget_snprintf(buf, bufsize, "%d%c", (int) (val + .5), powers[i]);
			return buf;
		}
		n /= 1024;
	}

	return NULL; /* unreached */
}

/**
 * \param[out] width Number of columns in terminal
 * \param[out] height Number of rows in terminal
 * \return Upon successful completion, \p wget_get_screen_size will return 0,
 * and the values of \p width and \p height will be set accordingly.
 * If an error was encountered, the function will return -1 without touching
 * the values of \p width and \p height.
 *
 * Get the size of the terminal to which the output is currently printed
 * (stderr). This function accepts two int pointers and will set their values
 * to the width and height of the active terminal in number of columns. If
 * either of the parameter is NULL, its value will not be set by the function.
 */
#ifdef HAVE_IOCTL
int wget_get_screen_size(int *width, int *height)
{
	struct winsize wsz;
	int fd = fileno(stderr); // TODO: progress bar is output to stdout so we probably should be using that !?

	if (ioctl (fd, TIOCGWINSZ, &wsz) >= 0) {
		if (width)
			*width = wsz.ws_col;
		if (height)
			*height = wsz.ws_row;

		return 0;
	}

	return -1;
}
#elif defined _WIN32
int wget_get_screen_size(int *width, int *height)
{
	static CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
	static HANDLE consoleHandle = NULL;

	if (consoleHandle == NULL)
		consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	if (!GetConsoleScreenBufferInfo(consoleHandle, &csbiInfo))
		return -1;

	if (width)
		*width = csbiInfo.dwSize.X;
	if (height)
		*height = csbiInfo.dwSize.Y;

	return 0;
}
#else
int wget_get_screen_size(WGET_GCC_UNUSED int *width, WGET_GCC_UNUSED int *height)
{
	return -1;
}
#endif

/**@}*/

/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 * Dynamic loading abstraction for object files
 *
 */

#ifndef SRC_WGET_DL_H
#define SRC_WGET_DL_H

#include <wget.h>

// Error handling for dynamic loader
typedef struct
{
	const char *msg;
} dl_error_t;

// Initializes the error object for catching errors
static inline void dl_error_init(dl_error_t *e)
{
	e->msg = NULL;
}

// Checks if the error is set
static inline int dl_error_is_set(dl_error_t *e)
{
	return e->msg ? 1 : 0;
}

// Gets the error message if error is set, else NULL
// Error string is owned by the error object and will be freed when error is
// unset.
static inline const char *dl_error_get_msg(dl_error_t *e)
{
	return e->msg;
}

// Set an error message. Call with msg=NULL to clear error.
void dl_error_set(dl_error_t *e, const char *msg);

// Set an error message with printf format.
void dl_error_set_printf
	(dl_error_t *e, const char *format, ...) WGET_GCC_PRINTF_FORMAT(2, 3);

// Returns 1 if dynamic loader will work on the current platform, 0 otherwise
int dl_supported(void);

// The dynamically loaded object file handle
typedef struct dl_file_st dl_file_t;

/* Opens an object file. If the operation fails NULL is returned
 * and error is set.
 */
dl_file_t *dl_file_open(const char *filename, dl_error_t *e);

/* Looks up a symbol in the loaded object file.
 * On success it returns a pointer to the symbol,
 * else it returns NULL and sets an error.
 */
void *dl_file_lookup(dl_file_t *dm, const char *symbol, dl_error_t *e);

// Unloads the loaded object file
void dl_file_close(dl_file_t *dm);

/* Builds a module name given a path to the object file.
 * Returns NULL if path does not match the pattern for object files and
 * strict is set to 1.
 * Free the returned string with wget_free().
 */
char *dl_get_name_from_path(const char *path, int strict);

/* Searches for an object file with a given name in the given list of
 * directories. If found it returns the filename, else returns NULL.
 * Free the returned string with wget_free().
 */
char *dl_search(const char *name, const wget_vector *dirs);

/* Creates a list of loadable object files in a given list of directories.
 */
void dl_list(const wget_vector *dirs, wget_vector *names_out);

#endif /* SRC_WGET_DL_H */

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

#include <config.h>

#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdarg.h>

#include <wget.h>

#include "wget_main.h"
#include "wget_dl.h"

// Error reporting functions

static void dl_error_set_noalloc(dl_error_t *e, const char *msg)
{
	if (msg && e->msg)
		wget_error_printf(_("Piling up error '%s' over error '%s'"), msg, e->msg);

	wget_free((void *) e->msg);
	e->msg = msg;
}

// Set an error message. Call with msg=NULL to clear error.
void dl_error_set(dl_error_t *e, const char *msg)
{
	dl_error_set_noalloc(e, wget_strdup(msg));
}

// Set an error message with printf format.
void dl_error_set_printf (dl_error_t *e, const char *format, ...)
{
	va_list arglist;

	va_start(arglist, format);
	dl_error_set_noalloc(e, wget_vaprintf(format, arglist));
	va_end(arglist);
}

#ifdef PLUGIN_SUPPORT
// If the string is not a path, converts to path by prepending "./" to it,
// else returns NULL
static char *convert_to_path_if_not(const char *str)
{
	if (str && !strchr(str, '/'))
		return wget_aprintf("./%s", str);

	return NULL;
}
#endif

#if defined PLUGIN_SUPPORT_LIBDL
#include <dlfcn.h>

int dl_supported(void)
{
	return 1;
}

struct dl_file_st
{
	void *handle;
};

// Opens an object file
dl_file_t *dl_file_open(const char *filename, dl_error_t *e)
{
	dl_file_t *dm = NULL;
	dl_file_t dm_st;
	char *buf = convert_to_path_if_not(filename);

	dm_st.handle = dlopen(buf ? buf : filename, RTLD_LAZY | RTLD_LOCAL);
	wget_xfree(buf);

	if (dm_st.handle)
		dm = wget_memdup(&dm_st, sizeof(dl_file_t));
	else
		dl_error_set(e, dlerror());

	return dm;
}

void *dl_file_lookup(dl_file_t *dm, const char *symbol, dl_error_t *e)
{
	void *res;
	char *error;

	res = dlsym(dm->handle, symbol);
	error = dlerror();
	if (error) {
		dl_error_set(e, error);
		return NULL;
	}

	return res;
}

void dl_file_close(dl_file_t *dm)
{
	dlclose(dm->handle);

	wget_free(dm);
}

#elif defined PLUGIN_SUPPORT_WINDOWS
#include <windows.h>

int dl_supported(void)
{
	return 1;
}

struct dl_file_st
{
	HMODULE handle;
};

static void dl_win32_set_last_error(dl_error_t *e)
{
	char *buf;

	DWORD error_code = GetLastError();

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
			| FORMAT_MESSAGE_IGNORE_INSERTS
			| FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, error_code, 0,
			(LPTSTR) &buf, 0, NULL);

	if (buf) {
		dl_error_set(e, buf);
		LocalFree(buf);
	} else {
		dl_error_set_printf(e, "Unknown error %d", (int) error_code);
	}
}

dl_file_t *dl_file_open(const char *filename, dl_error_t *e)
{
	dl_file_t *dm = NULL;
	dl_file_t dm_st;
	char *buf = convert_to_path_if_not(filename);

	dm_st.handle = LoadLibrary(buf ? buf : filename);
	wget_xfree(buf);

	if (dm_st.handle)
		dm = wget_memdup(&dm_st, sizeof(dl_file_t));
	else
		dl_win32_set_last_error(e);

	return dm;
}

void *dl_file_lookup(dl_file_t *dm, const char *symbol, dl_error_t *e)
{
	void *res = GetProcAddress(dm->handle, symbol);
	if (! res)
		dl_win32_set_last_error(e);
	return res;
}

void dl_file_close(dl_file_t *dm)
{
	FreeLibrary(dm->handle);
	wget_free(dm);
}

#else

static const char *dl_unsupported = "Dynamic loading is not supported on the current platform.";

int dl_supported(void)
{
	return 0;
}

dl_file_t *dl_file_open(WGET_GCC_UNUSED const char *filename, dl_error_t *e)
{
	dl_error_set(e, dl_unsupported);
	return NULL;
}

void *dl_file_lookup(WGET_GCC_UNUSED dl_file_t *dm, WGET_GCC_UNUSED const char *symbol, dl_error_t *e)
{
	dl_error_set(e, dl_unsupported);
	return NULL;
}

void dl_file_close(WGET_GCC_UNUSED dl_file_t *dm)
{
}

#endif

typedef struct {
	const char *prefix;
	const char *suffix;
} object_pattern_t;
#if defined _WIN32
#define PATTERNS {"lib", ".dll"}, {"", ".dll"}
#elif defined __APPLE__
#define PATTERNS {"lib", ".so"}, {"lib", ".bundle"}, {"lib", ".dylib"}
#elif defined __CYGWIN__
#define PATTERNS {"cyg", ".dll"}
#else
#define PATTERNS {"lib", ".so"}
#endif
static const object_pattern_t dl_patterns[] = {PATTERNS, {NULL, NULL}};
#undef PATTERNS

// Matches the given path with the patterns of a loadable object file
// and returns a range to use as a name
static int dl_match(const char *path, size_t *start_out, size_t *len_out)
{
	size_t i, mark;
	size_t start, len;

	// Strip everything but the filename
	mark = 0;
	for (i = 0; path[i]; i++) {
		if (path[i] == '/')
			mark = i + 1;
#ifdef _WIN32
		if (path[i] == '\\')
			mark = i + 1;
#endif // _WIN32
	}
	start = mark;
	len = i - start;

	// Match for the pattern and extract the name
	for (i = 0; dl_patterns[i].prefix; i++) {
		const char *p = dl_patterns[i].prefix;
		const char *s = dl_patterns[i].suffix;
		size_t pl = strlen(p);
		size_t sl = strlen(s);
		if (pl + sl >= len)
			continue;
		if (memcmp(path + start + len - sl, s, sl) == 0 && memcmp(path + start, p, pl) == 0) {
			start += pl;
			len -= (pl + sl);
			break;
		}
	}

	*start_out = start;
	*len_out = len;
	return dl_patterns[i].prefix ? 1 : 0;
}

static int is_regular_file(const char *filename)
{
	struct stat statbuf;

	if (stat(filename, &statbuf) < 0)
		return 0;
	if (S_ISREG(statbuf.st_mode))
		return 1;
	return 0;
}

char *dl_get_name_from_path(const char *path, int strict)
{
	size_t start, len;
	int match = dl_match(path, &start, &len);

	if (!match && strict)
		return NULL;
	else
		return wget_strmemdup(path + start, len);
}

char *dl_search(const char *name, const wget_vector *dirs)
{
	int n_dirs = wget_vector_size(dirs);

	for (int i = 0; i < n_dirs; i++) {
		const char *dir = wget_vector_get(dirs, i);
		if (dir && *dir) {
			for (int j = 0; dl_patterns[j].prefix; j++) {
				char *filename = wget_aprintf("%s/%s%s%s", dir,
						dl_patterns[j].prefix, name, dl_patterns[j].suffix);

				if (is_regular_file(filename))
					return filename;

				wget_free(filename);
			}
		} else {
			for (int j = 0; dl_patterns[j].prefix; j++) {
				char *filename = wget_aprintf("%s%s%s",
						dl_patterns[j].prefix, name, dl_patterns[j].suffix);

				if (is_regular_file(filename))
					return filename;

				wget_free(filename);
			}
		}
	}

	return NULL;
}

void dl_list(const wget_vector *dirs, wget_vector *names_out)
{
	int n_dirs = wget_vector_size(dirs);

	for (int i = 0; i < n_dirs; i++) {
		DIR *dirp;
		struct dirent *ent;
		const char *dir = wget_vector_get(dirs, i);

		dirp = opendir(dir);
		if (!dirp)
			continue;

		while((ent = readdir(dirp)) != NULL) {
			char *fname;
			char *name;

			fname = ent->d_name;

			// Ignore entries that don't match the pattern
			name = dl_get_name_from_path(fname, 1);
			if (! name)
				continue;

			// Ignore entries that are not regular files
			{
				char *sfname = wget_aprintf("%s/%s", dir, fname);
				int x = is_regular_file(sfname);
				wget_free(sfname);
				if (!x) {
					wget_free(name);
					continue;
				}
			}

			// Add to the list
			wget_vector_add(names_out, name);
		}

		closedir(dirp);
	}
}

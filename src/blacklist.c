/*
 * Copyright (c) 2012 Tim Ruehsen
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
 * IRI blacklist routines
 *
 * Changelog
 * 08.11.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <wget.h>

#include "wget_main.h"
#include "wget_options.h"
#include "wget_utils.h"
#include "wget_blacklist.h"

static wget_hashmap
	*blacklist;

static wget_thread_mutex
	mutex;

// generate the local filename corresponding to an URI
// respect the following options:
// --restrict-file-names (unix,windows,nocontrol,ascii,lowercase,uppercase)
// -nd / --no-directories
// -x / --force-directories
// -nH / --no-host-directories
// --protocol-directories
// --cut-dirs=number
// -P / --directory-prefix=prefix

WGET_GCC_NONNULL_ALL
static char * get_local_filename_real(const wget_iri *iri)
{
	wget_buffer buf;
	char *fname;
	bool directories;

	directories = config.recursive;

	if (config.directories == 0)
		directories = 0;

	if (config.force_directories == 1)
		directories = 1;

	wget_buffer_init(&buf, NULL, 256);

	if (config.directory_prefix && *config.directory_prefix) {
		wget_buffer_strcat(&buf, config.directory_prefix);
		wget_buffer_memcat(&buf, "/", 1);
	}

	if (directories) {
		if (config.protocol_directories && wget_iri_supported(iri)) {
			wget_buffer_strcat(&buf, wget_iri_scheme_get_name(iri->scheme));
			wget_buffer_memcat(&buf, "/", 1);
		}

		if (config.host_directories && iri->host && *iri->host) {
			wget_buffer_strcat(&buf, iri->host);
			wget_buffer_memcat(&buf, "/", 1);
		}

		if (config.cut_directories) {
			// cut directories
			wget_buffer path_buf;
			const char *p;
			int n;
			char sbuf[256];

			wget_buffer_init(&path_buf, sbuf, sizeof(sbuf));
			wget_iri_get_path(iri, &path_buf, config.local_encoding);

			for (n = 0, p = path_buf.data; n < config.cut_directories && p; n++) {
				p = strchr(*p == '/' ? p + 1 : p, '/');
			}

			if (!p && path_buf.data) {
				// we can't strip this many path elements, just use the filename
				p = strrchr(path_buf.data, '/');
				if (!p)
					p = path_buf.data;
			}

			if (p) {
				while (*p == '/')
					p++;

				wget_buffer_strcat(&buf, p);
			}

			wget_buffer_deinit(&path_buf);
		} else {
			wget_iri_get_path(iri, &buf, config.local_encoding);
		}

		if (config.cut_file_get_vars)
			fname = buf.data;
		else
			fname = wget_iri_get_query_as_filename(iri, &buf, config.local_encoding);
	} else {
		if (config.cut_file_get_vars)
			fname = wget_iri_get_basename(iri, &buf, config.local_encoding, 0); // without query part
		else
			fname = wget_iri_get_basename(iri, &buf, config.local_encoding, WGET_IRI_WITH_QUERY);
	}

	// do the filename escaping here
	if (config.restrict_file_names) {
		char tmp[1024];

		char *fname_esc = (sizeof(tmp) < buf.length * 3 + 1)
			? tmp
			: wget_malloc(buf.length * 3 + 1);

		if (wget_restrict_file_name(fname, fname_esc, config.restrict_file_names) != fname) {
			// escaping was really done, replace fname
			wget_buffer_strcpy(&buf, fname_esc);
			fname = buf.data;
		}

		if (fname_esc != tmp)
			xfree(fname_esc);
	}

	// create the complete directory path
//	mkdir_path(fname);

	debug_printf("local filename = '%s'\n", fname);

	return fname;
}

WGET_GCC_NONNULL_ALL
char * get_local_filename(const wget_iri *iri)
{
	if (config.delete_after)
		return NULL;

	if ((config.spider || config.output_document) && !config.continue_download)
		return NULL;

	return get_local_filename_real(iri);
}

// Paul Larson's hash function from Microsoft Research
// ~ O(1) insertion, search and removal
#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static WGET_GCC_NONNULL_ALL wget_hashmap_hash_fn hash_iri;
static unsigned int WGET_GCC_NONNULL_ALL hash_iri(const void *key)
{
	const wget_iri *iri = (wget_iri *) key;
	unsigned int h = iri->port; // use port as SALT if hash table attacks doesn't matter
	const unsigned char *p;

	h = h * 101 + iri->scheme;

	for (p = (unsigned char *)iri->host; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->path; p && *p; p++)
		h = h * 101 + *p;

	for (p = (unsigned char *)iri->query; p && *p; p++)
		h = h * 101 + *p;

	return h;
}

static WGET_GCC_NONNULL_ALL wget_hashmap_browse_fn blacklist_print_entry;
static int WGET_GCC_NONNULL_ALL blacklist_print_entry(void *ctx, const void *key, void *value)
{
	(void) ctx; (void) value;

	const wget_iri *iri = (wget_iri *) key;
	debug_printf("blacklist %s\n", iri->safe_uri);
	return 0;
}

static wget_hashmap_value_destructor free_value;
static void free_value(void *value)
{
	blacklist_entry *blacklistp = value;

	wget_xfree(blacklistp->local_filename);
	wget_iri_free((wget_iri **) &blacklistp->iri);
	wget_xfree(value);
}

void blacklist_init(void)
{
	wget_thread_mutex_init(&mutex);

	blacklist = wget_hashmap_create(128, hash_iri, (wget_hashmap_compare_fn *) wget_iri_compare);
	wget_hashmap_set_key_destructor(blacklist, NULL); // destroy the key (iri) in free_value()
	wget_hashmap_set_value_destructor(blacklist, free_value);
}

void blacklist_exit(void)
{
	wget_thread_mutex_destroy(&mutex);
}

/**
 * Only called outside multi-threading, no locking needed
 */
void blacklist_print(void)
{
	wget_hashmap_browse(blacklist, (wget_hashmap_browse_fn *) blacklist_print_entry, NULL);
}

/**
 * \param[in] iri wget_iri to put into the blacklist
 * \return A new blacklist_entry or %NULL if that \p iri was already known
 *
 * The given \p iri will be put into the blacklist.
 */
blacklist_entry *blacklist_add(const wget_iri *iri)
{
	blacklist_entry *entryp;

	wget_thread_mutex_lock(mutex);

	if (!wget_hashmap_get(blacklist, iri, &entryp)) {
		entryp = wget_malloc(sizeof(blacklist_entry));
		entryp->iri = iri;
		entryp->local_filename = get_local_filename(iri);

		// info_printf("Add to blacklist: %s\n",iri->uri);

		wget_hashmap_put(blacklist, iri, entryp);
		wget_thread_mutex_unlock(mutex);

		return entryp;
	}

	wget_thread_mutex_unlock(mutex);

	debug_printf("not requesting '%s'. (Already Seen)\n", iri->safe_uri);

	return NULL;
}

void blacklist_set_filename(blacklist_entry *blacklistp, const char *fname)
{
	if (!wget_strcmp(blacklistp->local_filename, fname))
		return;

	debug_printf("blacklist set filename: %s -> %s\n", blacklistp->local_filename, fname);

	// remove from blacklist, set new name and add again
	wget_hashmap_remove_nofree(blacklist, blacklistp->iri);
	xfree(blacklistp->local_filename);
	blacklistp->local_filename = wget_strdup(fname);

	wget_hashmap_put(blacklist, blacklistp->iri, blacklistp);
}

blacklist_entry *blacklist_get(const wget_iri *iri)
{
	blacklist_entry *entryp;

	if (wget_hashmap_get(blacklist, iri, &entryp))
		return entryp;

	return NULL;
}

/**
 * Only called outside multi-threading, no locking needed
 */
void blacklist_free(void)
{
	wget_hashmap_free(&blacklist);
}

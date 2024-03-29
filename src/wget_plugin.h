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
 * Plugin support implementation
 *
 */

#ifndef SRC_WGET_PLUGIN_H
#define SRC_WGET_PLUGIN_H

#include <wget.h>
#include "wget_dl.h"

// Needed for fuzzers that are compiled by C++
#ifdef __cplusplus
extern "C" {
#endif

// Initializes the plugin framework
void plugin_db_init(void);

// Sets a list of directories to search for plugins, separated by
// _separator_.
void plugin_db_add_search_paths(const char *paths, char separator);

// Clears list of directories to search for plugins
void plugin_db_clear_search_paths(void);

// Extended plugin handle
typedef struct
{
	wget_plugin parent;

	// Plugin name
	char *name;
	// Object file associated with the plugin
	dl_file_t *dm;
} plugin_t;

// Loads a plugin using its path. On failure it sets error and
// returns NULL.
plugin_t *plugin_db_load_from_path(const char *path, dl_error_t *e);

// Loads a plugin using its name. On failure it sets error and
// returns NULL.
plugin_t *plugin_db_load_from_name(const char *name, dl_error_t *e);

// Loads all plugins from environment variables. On any errors it
// logs them using wget_error_printf().
int plugin_db_load_from_envvar(void);

// Creates a list of all plugins found in plugin search paths.
void plugin_db_list(wget_vector *names_out);

// Forwards a command line option to appropriate plugin.
// On errors, it returns -1 and sets error. Otherwise it returns 0.
int plugin_db_forward_option(const char *plugin_option, dl_error_t *e);

// Returns whether any of the previous options forwarded was 'help'.
bool plugin_db_help_forwarded(void);

// Shows help from all loaded plugins
void plugin_db_show_help(void);

// Plugin's verdict on forwarded URLs
struct plugin_db_forward_url_verdict {
	wget_iri *alt_iri;
	char *alt_local_filename;
	bool
		reject : 1,
		accept : 1;
};

// Forwards a URL about to be enqueued to interested plugins
void plugin_db_forward_url(const wget_iri *iri, struct plugin_db_forward_url_verdict *verdict);

// Free's all contents of plugin_db_forward_url_verdict
void plugin_db_forward_url_verdict_free(struct plugin_db_forward_url_verdict *verdict);

// Forwards downloaded file to interested plugins
// Returns 0 if wget must not post-process the file, 1 otherwise
int plugin_db_forward_downloaded_file(const wget_iri *iri, int64_t size, const char *filename, const void *data,
		wget_vector *recurse_iris);

// Sends 'finalize' signal to all plugins and unloads all plugins
void plugin_db_finalize(int exitcode);

#ifdef __cplusplus
}
#endif

#endif /* SRC_WGET_PLUGIN_H */

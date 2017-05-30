/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
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

#ifndef _WGET_PLUGIN_H
#define _WGET_PLUGIN_H

//Initializes the plugin framework
void plugin_db_init(void);

//Sets a list of directories to search for plugins, separated by
//_separator_.
void plugin_db_add_search_paths(const char *paths, char separator);

//Clears list of directories to search for plugins
void plugin_db_clear_search_paths(void);

//Extended plugin handle
typedef struct
{
	wget_plugin_t parent;

	//Plugin name
	char *name;
	//Object file associated with the plugin
	dl_file_t *dm;
	//Finalizer function, to be called when wget2 exits
	wget_plugin_finalizer_t finalizer;
} plugin_t;

//Loads a plugin using its path. On failure it sets error and
//returns NULL.
plugin_t *plugin_db_load_from_path(const char *path, dl_error_t *e);

//Loads a plugin using its name. On failure it sets error and
//returns NULL.
plugin_t *plugin_db_load_from_name(const char *name, dl_error_t *e);

//Loads all plugins from environment variables. On any errors it
//logs them using wget_error_printf().
void plugin_db_load_from_envvar(void);

//Sends 'finalize' signal to all plugins and unloads all plugins
void plugin_db_finalize(int exitcode);

//Creates a list of all plugins found in plugin search paths.
void plugin_db_list(char ***names_out, size_t *n_names_out);

#endif //_WGET_PLUGIN_H

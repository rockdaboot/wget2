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

#include <config.h>

#include <string.h>
#include <stdbool.h>

#include <wget.h>

#include "wget_main.h"
#include "wget_dl.h"
#include "wget_plugin.h"

// Strings
static const char *plugin_list_envvar = "WGET2_PLUGINS";

// Splits string using the given separator and appends the array to vector.
static void split_string(const char *str, char separator, wget_vector *v)
{
	const char *ptr, *pmark;

	for (pmark = ptr = str; *ptr; pmark = ptr + 1) {
		if ((ptr = strchrnul(pmark, separator)) > pmark)
			wget_vector_add(v, wget_strmemdup(pmark, ptr - pmark));
	}
}

// Private members of the plugin
typedef struct {
	plugin_t parent;
	// Finalizer function, to be called when wget2 exits
	wget_plugin_finalizer_fn *finalizer;
	// The plugin's option processor
	wget_plugin_option_callback *argp;
	// The plugin's URL filter
	wget_plugin_url_filter_callback *url_filter;
	// The plugin's post processor
	wget_plugin_post_processor *post_processor;
	// Buffer to store plugin name
	char name_buf[];
} plugin_priv_t;

static bool initialized = false;
// Plugin search paths
static wget_vector *search_paths;
// List of loaded plugins
static wget_vector *plugin_list;
// Index of plugins by plugin name
static wget_stringmap *plugin_name_index;
// Whether any of the previous options forwarded was 'help'
static bool plugin_help_forwarded;

// Sets a list of directories to search for plugins, separated by
// _separator_.
void plugin_db_add_search_paths(const char *paths, char separator)
{
	split_string(paths, separator, search_paths);
}

// Clears list of directories to search for plugins
void plugin_db_clear_search_paths(void)
{
	wget_vector_clear(search_paths);
}

// Basic plugin API
static void impl_register_finalizer
	(wget_plugin *p_plugin, wget_plugin_finalizer_fn *fn)
{
	plugin_priv_t *priv = (plugin_priv_t *) p_plugin;

	priv->finalizer = fn;
}

static const char *impl_get_name(wget_plugin *p_plugin)
{
	plugin_t *plugin = (plugin_t *) p_plugin;

	return plugin->name;
}

static void impl_register_argp
	(wget_plugin *p_plugin, wget_plugin_option_callback *fn)
{
	plugin_priv_t *priv = (plugin_priv_t *) p_plugin;

	priv->argp = fn;
}

// API for URL interception
typedef struct {
	wget_intercept_action parent;

	struct plugin_db_forward_url_verdict verdict;
} intercept_action;

static void impl_action_reject(wget_intercept_action *p_action)
{
	intercept_action *action = (intercept_action *) p_action;

	action->verdict.reject = 1;
}

static void impl_action_accept(wget_intercept_action *p_action)
{
	intercept_action *action = (intercept_action *) p_action;

	action->verdict.accept = 1;
}

static void impl_action_set_alt_url(wget_intercept_action *p_action, const wget_iri *iri)
{
	intercept_action *action = (intercept_action *) p_action;

	if (action->verdict.alt_iri)
		wget_iri_free(&action->verdict.alt_iri);
	action->verdict.alt_iri = wget_iri_clone(iri);
}

static void impl_action_set_local_filename(wget_intercept_action *p_action, const char *local_filename)
{
	intercept_action *action = (intercept_action *) p_action;

	if (action->verdict.alt_local_filename)
		wget_free(action->verdict.alt_local_filename);
	action->verdict.alt_local_filename = wget_strdup(local_filename);
}

static void impl_register_url_filter(wget_plugin *p_plugin, wget_plugin_url_filter_callback *fn)
{
	plugin_priv_t *priv = (plugin_priv_t *) p_plugin;

	priv->url_filter = fn;
}

// API Exposed for plugins for intercepting downloaded files:
typedef struct {
	wget_downloaded_file parent;

	const wget_iri *iri;
	const char *filename;
	uint64_t size;
	const void *data;
	void *data_buf;
	wget_vector *recurse_iris;
} downloaded_file;

static const wget_iri *impl_file_get_source_url(wget_downloaded_file *p_file)
{
	downloaded_file *file = (downloaded_file *) p_file;

	return file->iri;
}

static const char *impl_file_get_local_filename(wget_downloaded_file *p_file)
{
	downloaded_file *file = (downloaded_file *) p_file;

	return file->filename;
}

static uint64_t impl_file_get_size(wget_downloaded_file *p_file)
{
	downloaded_file *file = (downloaded_file *) p_file;

	return file->size;
}

static int impl_file_get_contents(wget_downloaded_file *p_file, const void **data, size_t *size)
{
	downloaded_file *file = (downloaded_file *) p_file;

	if ((! file->data) && file->filename) {
		size_t dummy;
		file->data_buf = wget_read_file(file->filename, &dummy);
		if (! file->data_buf)
			return -1;
		file->data = file->data_buf;
	}

	*data = file->data;
	*size = file->size;

	return 0;
}

static FILE *impl_file_open_stream(wget_downloaded_file *p_file)
{
	downloaded_file *file = (downloaded_file *) p_file;

#ifdef HAVE_FMEMOPEN
	if (file->data)
		return fmemopen((void *) file->data, file->size, "rb");
#endif
	if (file->filename)
		return fopen(file->filename, "rb");
	return NULL;
}

static bool impl_file_get_recurse(wget_downloaded_file *p_file)
{
	downloaded_file *file = (downloaded_file *) p_file;

	return file->recurse_iris ? true : false;
}

static void impl_file_add_recurse_url(wget_downloaded_file *p_file, const wget_iri *iri)
{
	downloaded_file *file = (downloaded_file *) p_file;

	if (file->recurse_iris)
		wget_vector_add(file->recurse_iris, wget_iri_clone(iri));
}

static void impl_register_post_processor(wget_plugin *p_plugin, wget_plugin_post_processor *fn)
{
	plugin_priv_t *priv = (plugin_priv_t *) p_plugin;

	priv->post_processor = fn;
}

// vtable
static struct wget_plugin_vtable vtable = {
	.get_name = impl_get_name,
	.register_finalizer = impl_register_finalizer,
	.register_argp = impl_register_argp,

	.action_reject = impl_action_reject,
	.action_accept = impl_action_accept,
	.action_set_alt_url = impl_action_set_alt_url,
	.action_set_local_filename = impl_action_set_local_filename,
	.register_url_filter = impl_register_url_filter,

	.file_get_source_url = impl_file_get_source_url,
	.file_get_local_filename = impl_file_get_local_filename,
	.file_get_size = impl_file_get_size,
	.file_get_contents = impl_file_get_contents,
	.file_open_stream = impl_file_open_stream,
	.file_get_recurse = impl_file_get_recurse,
	.file_add_recurse_url = impl_file_add_recurse_url,
	.register_post_processor = impl_register_post_processor,
};

// Free resources of the plugin and plugin itself
static void plugin_free(plugin_t *plugin)
{
	dl_file_close(plugin->dm);
	wget_free(plugin);
}

// Loads a plugin located at given path and assign it a name
static plugin_t *load_plugin(const char *name, const char *path, dl_error_t *e)
{
	size_t name_len;
	dl_file_t *dm;
	plugin_t *plugin;
	plugin_priv_t *priv;
	wget_plugin_initializer_fn *init_fn;

	name_len = strlen(name);

	// Open object file
	dm = dl_file_open(path, e);
	if (! dm)
		return NULL;

	// Create plugin object
	plugin = wget_malloc(sizeof(plugin_priv_t) + name_len + 1);

	// Initialize private members
	priv = (plugin_priv_t *) plugin;
	priv->finalizer = NULL;
	priv->argp = NULL;
	priv->url_filter = NULL;
	priv->post_processor = NULL;
	wget_strscpy(priv->name_buf, name, name_len + 1);

	// Initialize public members
	plugin->parent.plugin_data = NULL;
	plugin->parent.vtable = &vtable;
	plugin->name = priv->name_buf;
	plugin->dm = dm;

	// Call initializer
	*((void **)(&init_fn)) = dl_file_lookup(dm, "wget_plugin_initializer", e);
	if (! init_fn) {
		plugin_free(plugin);
		return NULL;
	}
	if (init_fn((wget_plugin *) plugin) != 0) {
		dl_error_set(e, "Plugin failed to initialize");
		plugin_free(plugin);
		return NULL;
	}

	// Add to plugin list
	wget_vector_add(plugin_list, plugin);

	// Add to map
	wget_stringmap_put(plugin_name_index, plugin->name, plugin);

	return plugin;
}

// Loads a plugin using its path. On failure it sets error and
// returns NULL.
plugin_t *plugin_db_load_from_path(const char *path, dl_error_t *e)
{
	char *name = dl_get_name_from_path(path, 0);
	plugin_t *plugin = load_plugin(name, path, e);
	wget_free(name);
	return plugin;
}

// Loads a plugin using its name. On failure it sets error and
// returns NULL.
plugin_t *plugin_db_load_from_name(const char *name, dl_error_t *e)
{
	// Search where the plugin is
	plugin_t *plugin;

	char *filename = dl_search(name, search_paths);
	if (! filename) {
		dl_error_set_printf(e, "Plugin '%s' not found in any of the plugin search paths.",
				name);
		return NULL;
	}

	// Delegate
	plugin = load_plugin(name, filename, e);
	wget_free(filename);
	return plugin;
}

// Loads all plugins from environment variables. On any errors it
// logs them using wget_error_printf().
int plugin_db_load_from_envvar(void)
{
	dl_error_t e[1];
	wget_vector *v;
	const char *str;
	int ret = 0;

	// Fetch from environment variable
	str = getenv(plugin_list_envvar);

	if (str) {
#ifdef _WIN32
		char sep = ';';
#else
		char sep = ':';
#endif
		dl_error_init(e);

		// Split the value
		v = wget_vector_create(16, NULL);
		split_string(str, sep, v);

		// Load each plugin
		for (int i = 0; i < wget_vector_size(v) && ret == 0; i++) {
			plugin_t *plugin;
			int local = 0;

			str = (const char *) wget_vector_get(v, i);
			if (strchr(str, '/'))
				local = 1;
#ifdef _WIN32
			if (strchr(str, '\\'))
				local = 1;
#endif
			if (local)
				plugin = plugin_db_load_from_path(str, e);
			else
				plugin = plugin_db_load_from_name(str, e);

			if (! plugin) {
				wget_error_printf(_("Plugin '%s' failed to load: %s"), str, dl_error_get_msg(e));
				dl_error_set(e, NULL);
				ret = -1;
			}
		}

		wget_vector_free(&v);
	}

	return ret;
}

// Creates a list of all plugins found in plugin search paths.
void plugin_db_list(wget_vector *names_out)
{
	dl_list(search_paths, names_out);
}

// Forwards a command line option to appropriate plugin.
int plugin_db_forward_option(const char *plugin_option, dl_error_t *e)
{
	char *plugin_option_copy;
	char *plugin_name, *option, *value;
	char *ptr;
	plugin_t *plugin;
	plugin_priv_t *priv;
	int op_res;

	// Create writable copy of the input
	plugin_option_copy = wget_strdup(plugin_option);

	// Get plugin name
	ptr = strchr(plugin_option_copy, '.');
	if (! ptr) {
		dl_error_set_printf(e, "'%s': '.' is missing (separates plugin name and option)", plugin_option);
		wget_free(plugin_option_copy);
		return -1;
	}
	if (ptr == plugin_option_copy) {
		dl_error_set_printf(e, "'%s': Plugin name is missing.", plugin_option);
		wget_free(plugin_option_copy);
		return -1;
	}
	*ptr = 0;
	plugin_name = plugin_option_copy;

	// Split plugin option and value
	option = ptr + 1;
	ptr = strchr(option, '=');
	if (ptr) {
		*ptr = 0;
		value = ptr + 1;
	} else {
		value = NULL;
	}
	if (*option == 0) {
		dl_error_set_printf(e, "'%s': An option is required (after '.', and before '=' if present)",
				plugin_option);
		wget_free(plugin_option_copy);
		return -1;
	}

	// Handle '--help'
	if (strcmp(option, "help") == 0) {
		if (value) {
			dl_error_set_printf(e, "'help' option does not accept arguments\n");
			wget_free(plugin_option_copy);
			return -1;
		}
		plugin_help_forwarded = true;
	}

	// Search for plugin
	if (!wget_stringmap_get(plugin_name_index, plugin_name, &plugin)) {
		dl_error_set_printf(e, "Plugin '%s' is not loaded.", plugin_name);
		wget_free(plugin_option_copy);
		return -1;
	}
	priv = (plugin_priv_t *) plugin;
	if (! priv->argp) {
		dl_error_set_printf(e, "Plugin '%s' does not accept options.", plugin->name);
		wget_free(plugin_option_copy);
		return -1;
	}

	op_res = priv->argp((wget_plugin *) plugin, option, value);

	if (op_res < 0)
	{
		dl_error_set_printf(e, "Plugin '%s' did not accept option '%s'",
				plugin->name, strchrnul(plugin_option, '.'));
		wget_free(plugin_option_copy);
		return -1;
	}

	wget_free(plugin_option_copy);
	return 0;
}

// Shows help from all loaded plugins
void plugin_db_show_help(void)
{
	int n_plugins = wget_vector_size(plugin_list);

	for (int i = 0; i < n_plugins; i++) {
		plugin_t *plugin = (plugin_t *) wget_vector_get(plugin_list, i);
		plugin_priv_t *priv = (plugin_priv_t *) plugin;
		if (priv->argp) {
			printf(_("Options for %s:\n"), plugin->name);
			priv->argp((wget_plugin *) plugin, "help", NULL);
			printf("\n");
		}
	}
	plugin_help_forwarded = true;
}

// Returns 1 if any of the previous options forwarded was 'help'.
bool plugin_db_help_forwarded(void)
{
	return plugin_help_forwarded;
}

// Forwards a URL about to be enqueued to interested plugins
void plugin_db_forward_url(const wget_iri *iri, struct plugin_db_forward_url_verdict *verdict)
{
	// Initialize action structure
	intercept_action action = { .parent.vtable = &vtable };
	int n_plugins = wget_vector_size(plugin_list);

	for (int i = 0; i < n_plugins; i++) {
		plugin_t *plugin = (plugin_t *) wget_vector_get(plugin_list, i);
		plugin_priv_t *priv = (plugin_priv_t *) plugin;

		if (priv->url_filter) {
			const wget_iri *cur_iri = action.verdict.alt_iri;
			if (! cur_iri)
				cur_iri = iri;

			priv->url_filter((wget_plugin *) plugin, cur_iri, (wget_intercept_action *) &action);
			if (action.verdict.reject || action.verdict.accept)
				break;
		}
	}

	*verdict = action.verdict;
}

// Free's all contents of plugin_db_forward_url_verdict
void plugin_db_forward_url_verdict_free(struct plugin_db_forward_url_verdict *verdict)
{
	if (verdict->alt_iri)
		wget_iri_free(&verdict->alt_iri);
	if (verdict->alt_local_filename)
		wget_free(verdict->alt_local_filename);
}

// Forwards downloaded file to interested plugins
int plugin_db_forward_downloaded_file(const wget_iri *iri, int64_t size, const char *filename, const void *data,
		wget_vector *recurse_iris)
{
	int ret = 1;

	// Initialize the structure
	downloaded_file file = {
		.parent.vtable = &vtable,
		.iri = iri,
		.filename = filename,
		.size = size,
		.data = data,
		.data_buf = NULL,
		.recurse_iris = recurse_iris
	};

	// Forward to each plugin
	for (int i = 0; i < wget_vector_size(plugin_list); i++) {
		plugin_t *plugin = (plugin_t *) wget_vector_get(plugin_list, i);
		plugin_priv_t *priv = (plugin_priv_t *) plugin;

		if (priv->post_processor) {
			if (priv->post_processor((wget_plugin *) plugin, (wget_downloaded_file *) &file) == 0) {
				ret = 0;
				break;
			}
		}
	}

	// Cleanup
	if (file.data_buf)
		wget_free(file.data_buf);

	return ret;
}

// Initializes the plugin framework
void plugin_db_init(void)
{
	if (!initialized) {
		search_paths = wget_vector_create(16, NULL);
		plugin_list = wget_vector_create(16, NULL);
		wget_vector_set_destructor(plugin_list, (wget_vector_destructor *) plugin_free);
		plugin_name_index = wget_stringmap_create(16);
		wget_stringmap_set_key_destructor(plugin_name_index, NULL);
		wget_stringmap_set_value_destructor(plugin_name_index, NULL);
		plugin_help_forwarded = false;

		initialized = true;
	}
}

// Sends 'finalize' signal to all plugins and unloads all plugins
void plugin_db_finalize(int exitcode)
{
	if (!initialized)
		return;

	int n_plugins = wget_vector_size(plugin_list);

	for (int i = 0; i < n_plugins; i++) {
		plugin_t *plugin = (plugin_t *) wget_vector_get(plugin_list, i);
		plugin_priv_t *priv = (plugin_priv_t *) plugin;
		if (priv->finalizer)
			priv->finalizer((wget_plugin *) plugin, exitcode);
	}
	wget_vector_free(&plugin_list);
	wget_stringmap_free(&plugin_name_index);
	wget_vector_free(&search_paths);

	initialized = false;
}

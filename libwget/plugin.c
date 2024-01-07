/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
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
 * Plugin support
 *
 */

#include <config.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Plugin API for wget2
 * \defgroup libwget-plugin Plugin API for wget2
 * @{
 *
 * This is the plugin API for wget2.
 *
 * Each plugin must define a `wget_plugin_initializer()` function which will be called when the plugin is loaded.
 * See \ref wget_plugin_initializer_t "wget_plugin_initializer_t" for the prototype.
 * `wget_plugin_initializer()` must also be declared to be exported using `WGET_EXPORT`.
 */

/**
 * Gets the name the plugin is known as.
 * \param[in] plugin The plugin handle
 * \return the name of this plugin. The returned string is owned by wget and should not be freed or altered.
 */
const char *wget_plugin_get_name(wget_plugin *plugin)
{
	return plugin->vtable->get_name(plugin);
}

/**
 * Registers a function to be called when wget exits.
 * \param[in] plugin The plugin handle
 * \param[in] fn A function pointer to be called
 */
void wget_plugin_register_finalizer(wget_plugin *plugin, wget_plugin_finalizer_fn *fn)
{
	plugin->vtable->register_finalizer(plugin, fn);
}

/**
 * Registers a function for command line option forwarding.
 *
 * A option can be forwarded using an option following the pattern:
 *
 *     --plugin-opt=<plugin-name>.<option>[=<value>]
 *
 * \param[in] plugin The plugin handle
 * \param[in] fn The function pointer to register
 */
void wget_plugin_register_option_callback(wget_plugin *plugin, wget_plugin_option_callback *fn)
{
	plugin->vtable->register_argp(plugin, fn);
}

/**
 * Marks the intercepted URL to be rejected. The URL will not be fetched by wget2 or passed to remaining plugins.
 *
 * Mutually exclusive with `wget_intercept_action_accept()`.
 *
 * \param action Handle for any action taken by the plugin
 */
void wget_intercept_action_reject(wget_intercept_action *action)
{
	action->vtable->action_reject(action);
}

/**
 * Marks the intercepted URL to be accepted.
 * The URL will not be passed to remaining plugins. wget2 will not filter the URL by any accept or reject pattern.
 *
 * Mutually exclusive with `wget_intercept_action_reject()`.
 *
 * \param action Handle for any action taken by the plugin
 */
void wget_intercept_action_accept(wget_intercept_action *action)
{
	action->vtable->action_accept(action);
}

/**
 * Specifies an alternative URL to be fetched instead of the intercepted URL.
 *
 * \param action Handle for any action taken by the plugin
 * \param iri Alternative URL to be fetched
 */
void wget_intercept_action_set_alt_url(wget_intercept_action *action, const wget_iri *iri)
{
	action->vtable->action_set_alt_url(action, iri);
}

/**
 * Specifies that the fetched data from intercepted URL should be written to an alternative file.
 *
 * \param action Handle for any action taken by the plugin
 * \param local_filename Alternative file name to use
 */
void wget_intercept_action_set_local_filename(wget_intercept_action *action, const char *local_filename)
{
	action->vtable->action_set_local_filename(action, local_filename);
}

/**
 * Registers a plugin function for intercepting URLs
 *
 * The registered function will be passed an abstract object of type
 * \ref wget_intercept_action_t "wget_intercept_action_t" which can be used to influence how wget will process the
 * URL.
 *
 * \see wget_intercept_action_reject
 * \see wget_intercept_action_accept
 * \see wget_intercept_action_set_alt_url
 * \see wget_intercept_action_set_local_filename
 *
 * \param[in] plugin The plugin handle
 * \param[in] filter_fn The plugin function that will be passed the URL to be fetched
 */
void wget_plugin_register_url_filter_callback(wget_plugin *plugin, wget_plugin_url_filter_callback *filter_fn)
{
	plugin->vtable->register_url_filter(plugin, filter_fn);
}

/**
 * Gets the source address the file was downloaded from.
 *
 * \param[in] file Downloaded file handle
 * \return The address the file was downloaded from. The returned object is owned by wget and should not be free'd.
 */
const wget_iri *wget_downloaded_file_get_source_url(wget_downloaded_file *file)
{
	return file->vtable->file_get_source_url(file);
}

/**
 * Gets the file name the downloaded file was written to.
 *
 * \param[in] file Downloaded file handle
 * \return The file name the file was written to. The returned string is owned by wget and should not be free'd.
 */
const char *wget_downloaded_file_get_local_filename(wget_downloaded_file *file)
{
	return file->vtable->file_get_local_filename(file);
}

/**
 * Gets the size of the downloaded file.
 *
 * \param[in] file Downloaded file handle
 * \return The size of the downloaded file
 */
uint64_t wget_downloaded_file_get_size(wget_downloaded_file *file)
{
	return file->vtable->file_get_size(file);
}

/**
 * Reads the downloaded file into memory.
 *
 * Be careful, reading large files into memory can cause all sorts of problems like running out of memory.
 * Use \ref wget_downloaded_file_open_stream "wget_downloaded_file_open_stream()" whenever possible.
 *
 * \param[in] file Downloaded file handle
 * \param[out] data The contents of the downloaded file.
 *                  The memory is owned by wget and must not be free'd or modified.
 * \param[out] size Size of the downloaded file.
 */
int wget_downloaded_file_get_contents(wget_downloaded_file *file, const void **data, size_t *size)
{
	return file->vtable->file_get_contents(file, data, size);
}

/**
 * Opens the downloaded file as a new stream.
 *
 * \param[in] file Downloaded file handle
 * \return A newly opened stream for reading. The returned stream must be closed with fclose() after use.
 */
FILE *wget_downloaded_file_open_stream(wget_downloaded_file *file)
{
	return file->vtable->file_open_stream(file);
}

/**
 * Gets whether the downloaded file should be scanned for more URLs.
 *
 * \param[in] file Downloaded file handle
 * \return whether the file should be scanned for more URLs.
 */
bool wget_downloaded_file_get_recurse(wget_downloaded_file *file)
{
	return file->vtable->file_get_recurse(file);
}

/**
 * Adds a URL for recursive downloading. This function has no effect if
 * \ref wget_downloaded_file_get_recurse "wget_downloaded_file_get_recurse()" returns false.
 *
 * \param[in] file Downloaded file handle
 * \param[in] iri The URL to be fetched.
 */
void wget_downloaded_file_add_recurse_url(wget_downloaded_file *file, const wget_iri *iri)
{
	file->vtable->file_add_recurse_url(file, iri);
}

/**
 * Registers a plugin function for intercepting downloaded files.
 *
 * The registered function will be passed an abstract object of type
 * \ref wget_downloaded_file_t "wget_downloaded_file_t" which can be used to fetch the contents of the downloaded
 * files and adding parsed URLs for recursive downloading.
 *
 * \see wget_downloaded_file_get_source_url
 * \see wget_downloaded_file_get_local_filename
 * \see wget_downloaded_file_get_size
 * \see wget_downloaded_file_get_contents
 * \see wget_downloaded_file_open_stream
 * \see wget_downloaded_file_get_recurse
 * \see wget_downloaded_file_add_recurse_url
 *
 * \param[in] plugin The plugin handle
 * \param[in] fn The plugin function that will be passed a handle to downloaded files.
 *
 */
void
wget_plugin_register_post_processor(wget_plugin *plugin, wget_plugin_post_processor *fn)
{
	plugin->vtable->register_post_processor(plugin, fn);
}

/** @} */

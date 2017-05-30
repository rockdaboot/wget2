/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
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
 * Dummy plugins for plugin support testing
 *
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <wget.h>

#if defined TEST_SELECT_NAME
WGET_EXPORT int wget_plugin_initializer(wget_plugin_t *plugin);
int wget_plugin_initializer(wget_plugin_t *plugin)
{
	const char *name = wget_plugin_get_name(plugin);
	if (strcmp(name, "pluginname") != 0) {
		wget_error_printf
			("Plugin took a wrong name '%s'\n", name);
		exit(1);
	}

	FILE *stream = fopen("plugin-loaded.txt", "wb");
	if (! stream)
		wget_error_printf_exit("Cannot open plugin-loaded.txt: %s",
				strerror(errno));
	fprintf(stream, "Plugin loaded\n");
	fclose(stream);

	return 0;
}
#elif defined TEST_SELECT_EXITSTATUS
static void finalizer
	(G_GNUC_WGET_UNUSED wget_plugin_t *plugin, int exit_status)
{
	FILE *stream = fopen("exit-status.txt", "wb");
	if (! stream)
		wget_error_printf_exit("Cannot open exit-status.txt: %s",
				strerror(errno));
	fprintf(stream, "exit(%d)\n", exit_status);
	fclose(stream);
}
WGET_EXPORT int wget_plugin_initializer(wget_plugin_t *plugin);
int wget_plugin_initializer(wget_plugin_t *plugin)
{
	wget_plugin_register_finalizer(plugin, finalizer);
	return 0;
}
#else
#error One of the TEST_SELECT_* must be defined to build this file
#endif

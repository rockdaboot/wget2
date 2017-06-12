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
		wget_error_printf("Plugin took a wrong name '%s'\n", name);
		exit(1);
	}

	FILE *stream = fopen("plugin-loaded.txt", "wb");
	if (! stream)
		wget_error_printf_exit("Cannot open plugin-loaded.txt: %s", strerror(errno));
	fprintf(stream, "Plugin loaded\n");
	fclose(stream);

	return 0;
}
#elif defined TEST_SELECT_EXITSTATUS
static void finalizer(G_GNUC_WGET_UNUSED wget_plugin_t *plugin, int exit_status)
{
	FILE *stream = fopen("exit-status.txt", "wb");
	if (! stream)
		wget_error_printf_exit("Cannot open exit-status.txt: %s", strerror(errno));
	fprintf(stream, "exit(%d)\n", exit_status);
	fclose(stream);
}
WGET_EXPORT int wget_plugin_initializer(wget_plugin_t *plugin);
int wget_plugin_initializer(wget_plugin_t *plugin)
{
	wget_plugin_register_finalizer(plugin, finalizer);
	return 0;
}
#elif defined TEST_SELECT_FAULTY1
WGET_EXPORT void irrelevant(void);
void irrelevant(void)
{
}
#elif defined TEST_SELECT_FAULTY2
static void finalizer(G_GNUC_WGET_UNUSED wget_plugin_t *plugin, int exit_status)
{
	FILE *stream = fopen("exit-status.txt", "wb");
	if (! stream)
		wget_error_printf_exit("Cannot open exit-status.txt: %s", strerror(errno));
	fprintf(stream, "exit(%d)\n", exit_status);
	fclose(stream);
}
WGET_EXPORT int wget_plugin_initializer(wget_plugin_t *plugin);
int wget_plugin_initializer(wget_plugin_t *plugin)
{
	wget_plugin_register_finalizer(plugin, finalizer);
	wget_error_printf("Plugin failed to initialize, intentionally\n");
	return 1;
}
#elif defined TEST_SELECT_OPTIONS
struct option_filter {
	const char *name;
	int valid_without_val;
	int valid_with_val;
};
struct option_filter options[] = {
	{"x", 1, 1},
	{"y", 1, 0},
	{"z", 0, 1},
	{"alpha", 1, 1},
	{"beta", 1, 0},
	{"gamma", 0, 1},
	{NULL, 0, 0}
};
static int argp_fn(wget_plugin_t *plugin, const char *option, const char *value)
{
	// List of options the plugin accepts
	int i;

	// Simulate help output
	if (strcmp(option, "help") == 0) {
		for (i = 0; options[i].name; i++) {
			printf("--plugin-opt=%s.%s", wget_plugin_get_name(plugin), options[i].name);
			if (options[i].valid_without_val) {
				if (options[i].valid_with_val)
					printf("[=value]");
			} else {
				printf("=value");
			}
			printf("\tDescription for '%s'\n", options[i].name);
		}
		printf("--plugin-opt=%s.help\tPrint help message for this plugin\n", wget_plugin_get_name(plugin));
		return 0;
	}

	// Simulate option accept/reject
	for (i = 0; options[i].name; i++) {
		if (strcmp(option, options[i].name) == 0)
			break;
	}
	if (! options[i].name) {
		wget_error_printf("Unknown option %s\n", option);
		return -1;
	}
	if ((!options[i].valid_with_val) && value) {
		wget_error_printf("Option %s does not accept an argument.\n", option);
		return -1;
	}
	if ((!options[i].valid_without_val) && !value) {
		wget_error_printf("Option %s requires an argument\n", option);
		return -1;
	}

	// Append option to options.txt
	FILE *stream = fopen("options.txt", "ab");
	if (! stream)
		wget_error_printf_exit("Cannot open options.txt: %s", strerror(errno));
	if (value)
		fprintf(stream, "%s=%s\n", option, value);
	else
		fprintf(stream, "%s\n", option);
	fclose(stream);

	return 0;
}
WGET_EXPORT int wget_plugin_initializer(wget_plugin_t *plugin);
int wget_plugin_initializer(wget_plugin_t *plugin)
{
	wget_plugin_register_argp(plugin, argp_fn);
	return 0;
}
#else
#error One of the TEST_SELECT_* must be defined to build this file
#endif

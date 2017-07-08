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
#elif defined TEST_SELECT_API
// A very simple option parser for plugin
struct option;
typedef int (*option_parser)(const struct option *opt, const char *value);
struct option {
	const char *name;
	const char *arg_desc;
	const char *desc;
	option_parser fn;
	void *lptr;
};
static int parse_option(const struct option *options, wget_plugin_t *plugin, const char *option, const char *value)
{
	size_t i;

	// Handle help
	if (strcmp(option, "help") == 0) {
		for (i = 0; options[i].name; i++) {
			printf("--plugin-opt=%s.%s%s\t%s\n", wget_plugin_get_name(plugin),
				options[i].name, options[i].arg_desc, options[i].desc);
		}
		printf("--plugin-opt=%s.help\tShow this help\n", wget_plugin_get_name(plugin));
		return 0;
	}

	// Search for option
	for (i = 0; options[i].name; i++) {
		if (strcmp(option, options[i].name) == 0)
			break;
	}
	if (! options[i].name) {
		wget_error_printf("Unknown option %s\n", option);
		return -1;
	}

	// Delegate
	return (* options[i].fn)(options + i, value);
}

static int parse_string(const struct option *option, const char *value)
{
	char **strptr = (char **) option->lptr;

	if (! value) {
		wget_error_printf("%s: Value expected\n", option->name);
		return -1;
	}

	wget_xfree(*strptr);
	*strptr = wget_strdup(value);
	return 0;
}
struct pair {
	char *l;
	char *r;
};
static void free_pair(struct pair *p)
{
	wget_xfree(p->l);
	wget_xfree(p->r);
}
static int parse_pair(const struct option *option, const char *value)
{
	struct pair *p = (struct pair *) option->lptr;

	if (! value) {
		wget_error_printf("%s: Value expected\n", option->name);
		return -1;
	}

	const char *ptr = strchr(value, ':');

	if (ptr) {
		free_pair(p);
		p->l = wget_strmemdup(value, ptr - value);
		p->r = wget_strdup(ptr + 1);
	} else {
		wget_error_printf("%s: Expected ':'\n", option->name);
		return -1;
	}
	return 0;
}

typedef struct {
	char *reject;
	char *accept;
	struct pair replace;
	struct pair saveas;
} plugin_data_t;

static int argp_fn(wget_plugin_t *plugin, const char *option, const char *value)
{
	plugin_data_t *d = (plugin_data_t *) plugin->plugin_data;
	struct option options[] = {
		{"reject", "=substring", "Do not fetch URL containing substring",
			parse_string, (void *) &d->reject},
		{"accept", "=substring", "Force fetch URLs containing substring",
			parse_string, (void *) &d->accept},
		{"replace", "=substring:replacement", "Replace substring with replacement in URLs",
			parse_pair, (void *) &d->replace},
		{"saveas", "=substring:filename", "Save URLs containing substring as filename",
			parse_pair, (void *) &d->saveas},
		{NULL, NULL, NULL, NULL, NULL}
	};

	return parse_option(options, plugin, option, value);
}

static void finalizer(wget_plugin_t *plugin, G_GNUC_WGET_UNUSED int exit_status)
{
	plugin_data_t *d = (plugin_data_t *) plugin->plugin_data;

	wget_xfree(d->reject);
	wget_xfree(d->accept);
	free_pair(&d->replace);
	free_pair(&d->saveas);

	wget_xfree(plugin->plugin_data);
}

static void url_filter(wget_plugin_t *plugin, const wget_iri_t *iri, wget_intercept_action_t *action)
{
	plugin_data_t *d = (plugin_data_t *) plugin->plugin_data;

	if (d->reject && strstr(iri->uri, d->reject))
		wget_intercept_action_reject(action);
	if (d->accept && strstr(iri->uri, d->accept))
		wget_intercept_action_accept(action);
	if (d->saveas.l && strstr(iri->uri, d->saveas.l))
		wget_intercept_action_set_local_filename(action, d->saveas.r);
	if (d->replace.l) {
		const char *ptr, *find;
		size_t find_len;
		wget_buffer_t buf[1];
		wget_iri_t *alt_iri;

		wget_buffer_init(buf, NULL, 0);
		find_len = strlen(d->replace.l);

		for (ptr = iri->uri; (find = strstr(ptr, d->replace.l)); ptr = find + find_len) {
			wget_buffer_memcat(buf, ptr, find - ptr);
			wget_buffer_strcat(buf, d->replace.r);
		}
		wget_buffer_strcat(buf, ptr);

		alt_iri = wget_iri_parse(buf->data, "utf-8");
		if (! alt_iri) {
			fprintf(stderr, "Cannot parse URL after replacement (%s)\n", buf->data);
		}
		wget_intercept_action_set_alt_url(action, alt_iri);

		wget_iri_free(&alt_iri);
		wget_buffer_deinit(buf);
	}
}

WGET_EXPORT int wget_plugin_initializer(wget_plugin_t *plugin);
int wget_plugin_initializer(wget_plugin_t *plugin)
{
	plugin_data_t *d = (plugin_data_t *) wget_calloc(1, sizeof(plugin_data_t));

	plugin->plugin_data = d;
	wget_plugin_register_argp(plugin, argp_fn);
	wget_plugin_register_finalizer(plugin, finalizer);

	wget_plugin_register_url_filter(plugin, url_filter);
	return 0;
}
#else
#error One of the TEST_SELECT_* must be defined to build this file
#endif

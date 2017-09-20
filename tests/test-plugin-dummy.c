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
static struct option_filter {
	const char
		*name;
	bool
		valid_without_val : 1,
		valid_with_val : 1;
} options[] = {
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

// Separate assert definition because here assertions are part of the tests
#define test_assert(expr) \
do { \
	if (! (expr)) \
		wget_error_printf_exit(__FILE__ ":%d: Failed assertion [%s]\n", __LINE__, #expr); \
} while (0)

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

static int parse_boolean(const struct option *option, const char *value)
{
	int *intptr = (int *) option->lptr;
	int bool_val = 1;

	if (value && strcmp(value, "false") == 0)
		bool_val = 0;

	*intptr = bool_val;

	return 0;
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
	wget_vector_t *files_processed;

	char *reject;
	char *accept;
	struct pair replace;
	struct pair saveas;
	int parse_rot13;
	int only_rot13;
	int test_pp;
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
		{"parse-rot13", "[=false]", "Parse rot13 obfuscated links (default: false)",
			parse_boolean, (void *) &d->parse_rot13},
		{"only-rot13", "[=false]", "Parse only rot13 links (default: false)",
			parse_boolean, (void *) &d->only_rot13},
		{"test-pp", "[=false]", "Test post-processing API for consistency",
			parse_boolean, (void *) &d->test_pp},
		{NULL, NULL, NULL, NULL, NULL}
	};

	return parse_option(options, plugin, option, value);
}

static void finalizer(wget_plugin_t *plugin, G_GNUC_WGET_UNUSED int exit_status)
{
	plugin_data_t *d = (plugin_data_t *) plugin->plugin_data;

	if (d->test_pp) {
		int i;
		FILE *stream;

		wget_vector_sort(d->files_processed);
		test_assert((stream = fopen("files_processed.txt", "wb")));
		for (i = 0; i < wget_vector_size(d->files_processed); i++)
			fprintf(stream, "%s\n", (const char *) wget_vector_get(d->files_processed, i));
		fclose(stream);
	}
	wget_vector_free(&d->files_processed);

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

static int post_processor(wget_plugin_t *plugin, wget_downloaded_file_t *file)
{
	plugin_data_t *d = (plugin_data_t *) plugin->plugin_data;

	if (d->parse_rot13 && wget_downloaded_file_get_recurse(file)) {
		const char *data;
		size_t len, i, j;
		static const char *needle = "rot13(";

		wget_downloaded_file_get_contents(file, (const void **) &data, &len);

		// Since data is not null-terminated and may have null bytes, strstr() cannot be used here.
		j = 0;
		for (i = 0; i < len; i++) {
			if (needle[j]) {
				// No prefix table needed for "rot13("
				if (needle[j] == data[i])
					j++;
				else
					j = 0;
			} else {
				// Match found
				size_t end;
				for (end = i; end < len && data[end] && data[end] != ')'; end++)
					;
				if (end < len && end > i && data[end] == ')') {
					// Obfuscated URL found, now deobfuscate and add it
					char *url = wget_malloc(end - i + 1);
					size_t k;
					wget_iri_t *iri;

					for (k = 0; k < end - i; k++) {
						char c = data[i + k];
						if (c >= 'A' && c <= 'Z')
							c = (((c - 'A') + 13) % 26) + 'A';
						if (c >= 'a' && c <= 'z')
							c = (((c - 'a') + 13) % 26) + 'a';
						url[k] = c;
					}
					url[end - i] = 0;

					if ((iri = wget_iri_parse(url, "utf-8"))) {
						wget_downloaded_file_add_recurse_url(file, iri);
						wget_iri_free(&iri);
					}
					wget_free(url);

					i = end;
				}

				j = 0;
			}
		}
	}

	if (d->test_pp) {
		const wget_iri_t *iri = wget_downloaded_file_get_source_url(file);
		const char *data;
		size_t size;
		FILE *stream;

		// Compare downloaded file contents with wget_downloaded_file_get_contents()
		test_assert(wget_downloaded_file_get_contents(file, (const void **) &data, &size) == 0);

		// Compare wget_downloaded_file_get_size() against wget_downloaded_file_get_contents()
		test_assert(size == wget_downloaded_file_get_size(file));

		// Compare with file on disk
		const char *fname = wget_downloaded_file_get_local_filename(file);
		if (fname) {
			char *refdata;
			size_t refsize;
			test_assert((refdata = wget_read_file(fname, &refsize)));
			test_assert(refsize == size && "wget_read_file(fname, &refsize)");
			test_assert(memcmp(data, refdata, size) == 0);
			wget_free(refdata);
		}

		// Compare downloaded file contents with wget_downloaded_file_open_stream()
		stream = wget_downloaded_file_open_stream(file);
		if (stream) {
			size_t i;
			for (i = 0; i < size; i++)
				test_assert((int) data[i] == getc(stream));
			test_assert("At end of stream, wget_downloaded_file_open_stream(file)" && getc(stream) == EOF);
			fclose(stream);
		}

		// Update list of files processed
		{
			const char *basename = strrchr(iri->uri, '/');
			if (basename)
				wget_vector_add_str(d->files_processed, basename + 1);
		}
	}

	return d->only_rot13 ? 0 : 1;
}

WGET_EXPORT int wget_plugin_initializer(wget_plugin_t *plugin);
int wget_plugin_initializer(wget_plugin_t *plugin)
{
	plugin_data_t *d = (plugin_data_t *) wget_calloc(1, sizeof(plugin_data_t));

	d->files_processed = wget_vector_create(4, -2, (wget_vector_compare_t) strcmp);

	plugin->plugin_data = d;
	wget_plugin_register_argp(plugin, argp_fn);
	wget_plugin_register_finalizer(plugin, finalizer);

	wget_plugin_register_url_filter(plugin, url_filter);
	wget_plugin_register_post_processor(plugin, post_processor);

	return 0;
}

#elif defined TEST_SELECT_DATABASE

// HPKP database for testing
static int hpkp_db_load_counter = 0;
typedef struct {
	wget_hpkp_db_t parent;
	wget_hpkp_db_t *backend_db;
} test_hpkp_db_t;
static int test_hpkp_db_load(wget_hpkp_db_t *p_hpkp_db)
{
	test_hpkp_db_t *hpkp_db = (test_hpkp_db_t *) p_hpkp_db;

	if (! hpkp_db->backend_db)
		wget_error_printf_exit("wget using wrong HPKP database\n");

	hpkp_db_load_counter++;
	return wget_hpkp_db_load(hpkp_db->backend_db);
}
static int test_hpkp_db_save(wget_hpkp_db_t *p_hpkp_db)
{
	test_hpkp_db_t *hpkp_db = (test_hpkp_db_t *) p_hpkp_db;

	if (! hpkp_db->backend_db)
		wget_error_printf_exit("wget using wrong HPKP database\n");

	return wget_hpkp_db_save(hpkp_db->backend_db);
}
static void test_hpkp_db_free(wget_hpkp_db_t *p_hpkp_db)
{
	test_hpkp_db_t *hpkp_db = (test_hpkp_db_t *) p_hpkp_db;

	if (hpkp_db->backend_db)
		wget_hpkp_db_free(&hpkp_db->backend_db);
	wget_free(hpkp_db);
}
static void test_hpkp_db_add(wget_hpkp_db_t *p_hpkp_db, wget_hpkp_t *hpkp)
{
	test_hpkp_db_t *hpkp_db = (test_hpkp_db_t *) p_hpkp_db;

	if (! hpkp_db->backend_db)
		wget_error_printf_exit("wget using wrong HPKP database\n");

	wget_hpkp_db_add(hpkp_db->backend_db, &hpkp);
}
static int test_hpkp_db_check_pubkey(wget_hpkp_db_t *p_hpkp_db, const char *host, const void *pubkey, size_t pubkeysize)
{
	test_hpkp_db_t *hpkp_db = (test_hpkp_db_t *) p_hpkp_db;

	if (! hpkp_db->backend_db)
		wget_error_printf_exit("wget using wrong HPKP database\n");

	return wget_hpkp_db_check_pubkey(hpkp_db->backend_db, host, pubkey, pubkeysize);
}
static struct wget_hpkp_db_vtable test_hpkp_db_vtable = {
	.load = test_hpkp_db_load,
	.save = test_hpkp_db_save,
	.free = test_hpkp_db_free,
	.add = test_hpkp_db_add,
	.check_pubkey = test_hpkp_db_check_pubkey
};
static wget_hpkp_db_t *test_hpkp_db_new(int usable) {
	test_hpkp_db_t *hpkp_db = wget_malloc(sizeof(test_hpkp_db_t));

	hpkp_db->parent.vtable = &test_hpkp_db_vtable;
	if (usable)
		hpkp_db->backend_db = wget_hpkp_db_init(NULL, NULL);
	else
		hpkp_db->backend_db = NULL;

	return (wget_hpkp_db_t *) hpkp_db;
}

// HSTS database for testing
static int hsts_db_load_counter = 0;
typedef struct {
	wget_hsts_db_t parent;
	wget_hsts_db_t *backend_db;
} test_hsts_db_t;
static int test_hsts_db_load(wget_hsts_db_t *p_hsts_db)
{
	test_hsts_db_t *hsts_db = (test_hsts_db_t *) p_hsts_db;

	if (! hsts_db->backend_db)
		wget_error_printf_exit("wget using wrong HSTS database\n");

	hsts_db_load_counter++;
	return wget_hsts_db_load(hsts_db->backend_db);
}
static int test_hsts_db_save(wget_hsts_db_t *p_hsts_db)
{
	test_hsts_db_t *hsts_db = (test_hsts_db_t *) p_hsts_db;

	if (! hsts_db->backend_db)
		wget_error_printf_exit("wget using wrong HSTS database\n");

	return wget_hsts_db_save(hsts_db->backend_db);
}
static void test_hsts_db_free(wget_hsts_db_t *p_hsts_db)
{
	test_hsts_db_t *hsts_db = (test_hsts_db_t *) p_hsts_db;

	if (hsts_db->backend_db)
		wget_hsts_db_free(&hsts_db->backend_db);
	wget_free(hsts_db);
}
static void test_hsts_db_add(wget_hsts_db_t *p_hsts_db, const char *host, uint16_t port, time_t maxage, int include_subdomains)
{
	test_hsts_db_t *hsts_db = (test_hsts_db_t *) p_hsts_db;

	if (! hsts_db->backend_db)
		wget_error_printf_exit("wget using wrong HSTS database\n");

	wget_hsts_db_add(hsts_db->backend_db, host, port, maxage, include_subdomains);
}
static int test_hsts_db_host_match(const wget_hsts_db_t *p_hsts_db, const char *host, uint16_t port)
{
	const test_hsts_db_t *hsts_db = (test_hsts_db_t *) p_hsts_db;

	if (! hsts_db->backend_db)
		wget_error_printf_exit("wget using wrong HSTS database\n");

	return wget_hsts_host_match(hsts_db->backend_db, host, port);
}
static struct wget_hsts_db_vtable test_hsts_db_vtable = {
	.load = test_hsts_db_load,
	.save = test_hsts_db_save,
	.free = test_hsts_db_free,
	.add = test_hsts_db_add,
	.host_match = test_hsts_db_host_match
};
static wget_hsts_db_t *test_hsts_db_new(int usable)
{
	test_hsts_db_t *hsts_db = wget_malloc(sizeof(test_hsts_db_t));

	hsts_db->parent.vtable = &test_hsts_db_vtable;
	if (usable)
		hsts_db->backend_db = wget_hsts_db_init(NULL, NULL);
	else
		hsts_db->backend_db = NULL;

	return (wget_hsts_db_t *) hsts_db;
}

// OCSP database for testing
static int ocsp_db_load_counter = 0;
typedef struct {
	wget_ocsp_db_t parent;
	wget_ocsp_db_t *backend_db;
} test_ocsp_db_t;
static int test_ocsp_db_load(wget_ocsp_db_t *p_ocsp_db)
{
	test_ocsp_db_t *ocsp_db = (test_ocsp_db_t *) p_ocsp_db;

	if (! ocsp_db->backend_db)
		wget_error_printf_exit("wget using wrong OCSP database\n");

	ocsp_db_load_counter++;
	return wget_ocsp_db_load(ocsp_db->backend_db);
}
static int test_ocsp_db_save(wget_ocsp_db_t *p_ocsp_db)
{
	test_ocsp_db_t *ocsp_db = (test_ocsp_db_t *) p_ocsp_db;

	if (! ocsp_db->backend_db)
		wget_error_printf_exit("wget using wrong OCSP database\n");

	return wget_ocsp_db_save(ocsp_db->backend_db);
}
static void test_ocsp_db_free(wget_ocsp_db_t *p_ocsp_db)
{
	test_ocsp_db_t *ocsp_db = (test_ocsp_db_t *) p_ocsp_db;

	if (ocsp_db->backend_db)
		wget_ocsp_db_free(&ocsp_db->backend_db);
	wget_free(ocsp_db);
}
static void test_ocsp_db_add_fingerprint(wget_ocsp_db_t *p_ocsp_db, const char *fingerprint, time_t maxage, int valid)
{
	test_ocsp_db_t *ocsp_db = (test_ocsp_db_t *) p_ocsp_db;

	if (! ocsp_db->backend_db)
		wget_error_printf_exit("wget using wrong OCSP database\n");

	wget_ocsp_db_add_fingerprint(ocsp_db->backend_db, fingerprint, maxage, valid);
}
static void test_ocsp_db_add_host(wget_ocsp_db_t *p_ocsp_db, const char *host, time_t maxage)
{
	test_ocsp_db_t *ocsp_db = (test_ocsp_db_t *) p_ocsp_db;

	if (! ocsp_db->backend_db)
		wget_error_printf_exit("wget using wrong OCSP database\n");

	wget_ocsp_db_add_host(ocsp_db->backend_db, host, maxage);
}
static bool test_ocsp_db_fingerprint_in_cache(const wget_ocsp_db_t *p_ocsp_db, const char *fingerprint, int *valid)
{
	const test_ocsp_db_t *ocsp_db = (test_ocsp_db_t *) p_ocsp_db;

	if (! ocsp_db->backend_db)
		wget_error_printf_exit("wget using wrong OCSP database\n");

	return wget_ocsp_fingerprint_in_cache(ocsp_db->backend_db, fingerprint, valid);
}
static bool test_ocsp_db_hostname_is_valid(const wget_ocsp_db_t *p_ocsp_db, const char *hostname)
{
	const test_ocsp_db_t *ocsp_db = (test_ocsp_db_t *) p_ocsp_db;

	if (! ocsp_db->backend_db)
		wget_error_printf_exit("wget using wrong OCSP database\n");

	return wget_ocsp_hostname_is_valid(ocsp_db->backend_db, hostname);
}
static struct wget_ocsp_db_vtable test_ocsp_db_vtable = {
	.load = test_ocsp_db_load,
	.save = test_ocsp_db_save,
	.free = test_ocsp_db_free,
	.add_fingerprint = test_ocsp_db_add_fingerprint,
	.add_host = test_ocsp_db_add_host,
	.fingerprint_in_cache = test_ocsp_db_fingerprint_in_cache,
	.hostname_is_valid = test_ocsp_db_hostname_is_valid
};
static wget_ocsp_db_t *test_ocsp_db_new(int usable) {
	test_ocsp_db_t *ocsp_db = wget_malloc(sizeof(test_ocsp_db_t));

	ocsp_db->parent.vtable = &test_ocsp_db_vtable;
	if (usable)
		ocsp_db->backend_db = wget_ocsp_db_init(NULL, NULL);
	else
		ocsp_db->backend_db = NULL;

	return (wget_ocsp_db_t *) ocsp_db;
}

static void finalizer(G_GNUC_WGET_UNUSED wget_plugin_t *plugin, G_GNUC_WGET_UNUSED int exit_status)
{
	if (hpkp_db_load_counter != 1)
		wget_error_printf_exit("wget using wrong HPKP database (%d)\n", hpkp_db_load_counter);
	if (hsts_db_load_counter != 1)
		wget_error_printf_exit("wget using wrong HSTS database (%d)\n", hsts_db_load_counter);
	if (ocsp_db_load_counter != 1)
		wget_error_printf_exit("wget using wrong OCSP database (%d)\n", ocsp_db_load_counter);
}

WGET_EXPORT int wget_plugin_initializer(wget_plugin_t *plugin);
int wget_plugin_initializer(wget_plugin_t *plugin)
{
	wget_plugin_add_hpkp_db(plugin, test_hpkp_db_new(0), 1);
	wget_plugin_add_hpkp_db(plugin, test_hpkp_db_new(1), 3);
	wget_plugin_add_hpkp_db(plugin, test_hpkp_db_new(0), 2);

	wget_plugin_add_hsts_db(plugin, test_hsts_db_new(0), 1);
	wget_plugin_add_hsts_db(plugin, test_hsts_db_new(1), 3);
	wget_plugin_add_hsts_db(plugin, test_hsts_db_new(0), 2);

	wget_plugin_add_ocsp_db(plugin, test_ocsp_db_new(0), 1);
	wget_plugin_add_ocsp_db(plugin, test_ocsp_db_new(1), 3);
	wget_plugin_add_ocsp_db(plugin, test_ocsp_db_new(0), 2);

	wget_plugin_register_finalizer(plugin, finalizer);

	return 0;
}

#else
#error One of the TEST_SELECT_* must be defined to build this file
#endif

/*
 * Copyright (c) 2017-2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget
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
 * along with Wget  If not, see <https://www.gnu.org/licenses/>.
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
WGET_EXPORT int wget_plugin_initializer(wget_plugin *plugin);
int wget_plugin_initializer(wget_plugin *plugin)
{
	const char *name = wget_plugin_get_name(plugin);
	if (strcmp(name, "pluginname") != 0) {
		wget_error_printf("Plugin took a wrong name '%s'\n", name);
		exit(EXIT_FAILURE);
	}

	FILE *stream = fopen("plugin-loaded.txt", "wb");
	if (! stream)
		wget_error_printf_exit("Cannot open plugin-loaded.txt: %s", strerror(errno));
	wget_fprintf(stream, "Plugin loaded\n");
	fclose(stream);

	return 0;
}
#elif defined TEST_SELECT_EXITSTATUS
static void finalizer(WGET_GCC_UNUSED wget_plugin *plugin, int exit_status)
{
	FILE *stream = fopen("exit-status.txt", "wb");
	if (! stream)
		wget_error_printf_exit("Cannot open exit-status.txt: %s", strerror(errno));
	wget_fprintf(stream, "exit(%d)\n", exit_status);
	fclose(stream);
}
WGET_EXPORT int wget_plugin_initializer(wget_plugin *plugin);
int wget_plugin_initializer(wget_plugin *plugin)
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
static void finalizer(WGET_GCC_UNUSED wget_plugin *plugin, int exit_status)
{
	FILE *stream = fopen("exit-status.txt", "wb");
	if (! stream)
		wget_error_printf_exit("Cannot open exit-status.txt: %s", strerror(errno));
	wget_fprintf(stream, "exit(%d)\n", exit_status);
	fclose(stream);
}
WGET_EXPORT int wget_plugin_initializer(wget_plugin *plugin);
int wget_plugin_initializer(wget_plugin *plugin)
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
static int argp_fn(wget_plugin *plugin, const char *option, const char *value)
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
		wget_fprintf(stream, "%s=%s\n", option, value);
	else
		wget_fprintf(stream, "%s\n", option);
	fclose(stream);

	return 0;
}
WGET_EXPORT int wget_plugin_initializer(wget_plugin *plugin);
int wget_plugin_initializer(wget_plugin *plugin)
{
	wget_plugin_register_option_callback(plugin, argp_fn);
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
static int parse_option(const struct option *options, wget_plugin *plugin, const char *option, const char *value)
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
	wget_vector *files_processed;

	char *reject;
	char *accept;
	struct pair replace;
	struct pair saveas;
	int parse_rot13;
	int only_rot13;
	int test_pp;
} plugin_data_t;

static int argp_fn(wget_plugin *plugin, const char *option, const char *value)
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

static void finalizer(wget_plugin *plugin, WGET_GCC_UNUSED int exit_status)
{
	plugin_data_t *d = (plugin_data_t *) plugin->plugin_data;

	if (d->test_pp) {
		int i;
		FILE *stream;

		wget_vector_sort(d->files_processed);
		test_assert((stream = fopen("files_processed.txt", "wb")));
		for (i = 0; i < wget_vector_size(d->files_processed); i++)
			wget_fprintf(stream, "%s\n", (const char *) wget_vector_get(d->files_processed, i));
		fclose(stream);
	}
	wget_vector_free(&d->files_processed);

	wget_xfree(d->reject);
	wget_xfree(d->accept);
	free_pair(&d->replace);
	free_pair(&d->saveas);

	wget_xfree(plugin->plugin_data);
}

static void url_filter(wget_plugin *plugin, const wget_iri *iri, wget_intercept_action *action)
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
		wget_buffer buf[1];
		wget_iri *alt_iri;

		wget_buffer_init(buf, NULL, 0);
		find_len = strlen(d->replace.l);

		for (ptr = iri->uri; (find = strstr(ptr, d->replace.l)); ptr = find + find_len) {
			wget_buffer_memcat(buf, ptr, find - ptr);
			wget_buffer_strcat(buf, d->replace.r);
		}
		wget_buffer_strcat(buf, ptr);

		alt_iri = wget_iri_parse(buf->data, "utf-8");
		if (! alt_iri) {
			wget_fprintf(stderr, "Cannot parse URL after replacement (%s)\n", buf->data);
		}
		wget_intercept_action_set_alt_url(action, alt_iri);

		wget_iri_free(&alt_iri);
		wget_buffer_deinit(buf);
	}
}

static int post_processor(wget_plugin *plugin, wget_downloaded_file *file)
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
					wget_iri *iri;

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
		const wget_iri *iri = wget_downloaded_file_get_source_url(file);
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
				wget_vector_add(d->files_processed, wget_strdup(basename + 1));
		}
	}

	return d->only_rot13 ? 0 : 1;
}

WGET_EXPORT int wget_plugin_initializer(wget_plugin *plugin);
int wget_plugin_initializer(wget_plugin *plugin)
{
	plugin_data_t *d = (plugin_data_t *) wget_calloc(1, sizeof(plugin_data_t));

	d->files_processed = wget_vector_create(4, (wget_vector_compare_fn *) strcmp);

	plugin->plugin_data = d;
	wget_plugin_register_option_callback(plugin, argp_fn);
	wget_plugin_register_finalizer(plugin, finalizer);

	wget_plugin_register_url_filter_callback(plugin, url_filter);
	wget_plugin_register_post_processor(plugin, post_processor);

	return 0;
}

#elif defined TEST_SELECT_DATABASE

// HPKP database for testing
static int hpkp_db_load_counter = 0;

// this is a dummy hpkp db implementation for the plugin
typedef struct {
	int dummy;
} test_hpkp_db;

static wget_hpkp_db *test_hpkp_db_init(wget_hpkp_db *hpkp_db, const char *fname)
{
	(void) fname;

	if (!hpkp_db)
		hpkp_db = wget_calloc(1, sizeof(test_hpkp_db));
	else
		memset(hpkp_db, 0, sizeof(test_hpkp_db));

	return hpkp_db;
}

static void test_hpkp_db_deinit(wget_hpkp_db *hpkp_db)
{
	if (hpkp_db) {
		memset(hpkp_db, 0, sizeof(test_hpkp_db));
	}
}

static void test_hpkp_db_free(wget_hpkp_db **hpkp_db)
{
	wget_free(*hpkp_db);
	*hpkp_db = NULL;
}

static int test_hpkp_db_check_pubkey(wget_hpkp_db *hpkp_db, const char *host, const void *pubkey, size_t pubkeysize)
{
	(void) hpkp_db;
	wget_debug_printf("%s: host %s pubkey %p pksize %zu\n", __func__,
		host, pubkey, pubkeysize);

	return 0;
}

static void test_hpkp_db_add(wget_hpkp_db *hpkp_db, wget_hpkp **hpkp)
{
	(void) hpkp_db;
	wget_debug_printf("%s: hpkp %p\n", __func__, (void *) hpkp);
}

static int test_hpkp_db_load(wget_hpkp_db *hpkp_db)
{
	(void) hpkp_db;
	hpkp_db_load_counter++;
	return 0;
}

static int test_hpkp_db_save(wget_hpkp_db *hpkp_db)
{
	(void) hpkp_db;
	return 0;
}

static wget_hpkp_db_vtable test_hpkp_db_vtable = {
	.init = test_hpkp_db_init,
	.deinit = test_hpkp_db_deinit,
	.free = test_hpkp_db_free,
	.check_pubkey = test_hpkp_db_check_pubkey,
	.add = test_hpkp_db_add,
	.load = test_hpkp_db_load,
	.save = test_hpkp_db_save,
};


// HSTS database for testing
static int hsts_db_load_counter = 0;

// this is a dummy hsts db implementation for the plugin
typedef struct {
	int dummy;
} test_hsts_db_t;

static int test_hsts_db_host_match(const wget_hsts_db *hsts_db, const char *host, uint16_t port)
{
	(void) hsts_db;

	wget_debug_printf("%s: host %s port %hu\n", __func__,
		host, port);

	return 0;
}

static wget_hsts_db *test_hsts_db_init(wget_hsts_db *hsts_db, const char *fname)
{
	(void) fname;

	if (!hsts_db)
		hsts_db = wget_calloc(1, sizeof(test_hsts_db_t));
	else
		memset(hsts_db, 0, sizeof(test_hsts_db_t));

	return hsts_db;
}

static void test_hsts_db_deinit(wget_hsts_db *hsts_db)
{
	if (hsts_db) {
		memset(hsts_db, 0, sizeof(test_hsts_db_t));
	}
}

static void test_hsts_db_free(wget_hsts_db **hsts_db)
{
	wget_free(*hsts_db);
	*hsts_db = NULL;
}

static void test_hsts_db_add(wget_hsts_db *hsts_db, const char *host, uint16_t port, int64_t maxage, bool include_subdomains)
{
	(void) hsts_db;
	wget_debug_printf("%s: host %s port %hu maxage %lld include_subdomains %d\n", __func__,
		host, port, (long long) maxage, include_subdomains);
}

static int test_hsts_db_load(wget_hsts_db *hsts_db)
{
	(void) hsts_db;
	hsts_db_load_counter++;
	return 0;
}

static int test_hsts_db_save(wget_hsts_db *hsts_db)
{
	(void) hsts_db;
	return 0;
}

static const wget_hsts_db_vtable test_hsts_db_vtable = {
	.host_match = test_hsts_db_host_match,
	.init = test_hsts_db_init,
	.deinit = test_hsts_db_deinit,
	.free = test_hsts_db_free,
	.add = test_hsts_db_add,
	.load = test_hsts_db_load,
	.save = test_hsts_db_save,
};

// OCSP database for testing
static int ocsp_db_load_counter = 0;

// this is a dummy ocsp db implementation for the plugin
typedef struct {
	int dummy;
} test_ocsp_db;

static wget_ocsp_db *test_ocsp_db_init(wget_ocsp_db *ocsp_db, const char *fname)
{
	(void) fname;

	if (!ocsp_db)
		ocsp_db = wget_calloc(1, sizeof(test_ocsp_db));
	else
		memset(ocsp_db, 0, sizeof(test_ocsp_db));

	return ocsp_db;
}

static void test_ocsp_db_deinit(wget_ocsp_db *ocsp_db)
{
	if (ocsp_db) {
		memset(ocsp_db, 0, sizeof(test_ocsp_db));
	}
}

static void test_ocsp_db_free(wget_ocsp_db **ocsp_db)
{
	wget_free(*ocsp_db);
	*ocsp_db = NULL;
}

static bool test_ocsp_db_fingerprint_in_cache(const wget_ocsp_db *ocsp_db, const char *fingerprint, int *valid)
{
	(void) ocsp_db; (void) valid;

	wget_debug_printf("%s: fingerprint %s\n", __func__, fingerprint);

	return false;
}

static bool test_ocsp_db_hostname_is_valid(const wget_ocsp_db *ocsp_db, const char *hostname)
{
	(void) ocsp_db;

	wget_debug_printf("%s: hostname %s\n", __func__, hostname);

	return true;
}

static void test_ocsp_db_add_fingerprint(wget_ocsp_db *ocsp_db, const char *fingerprint, int64_t maxage, bool valid)
{
	(void) ocsp_db;

	wget_debug_printf("%s: fingerprint %s maxage %lld valid %d\n", __func__, fingerprint, (long long) maxage, valid);
}

static void test_ocsp_db_add_host(wget_ocsp_db *ocsp_db, const char *host, int64_t maxage)
{
	(void) ocsp_db;

	wget_debug_printf("%s: host %s maxage %lld\n", __func__, host, (long long) maxage);
}

static int test_ocsp_db_load(wget_ocsp_db *ocsp_db)
{
	(void) ocsp_db;
	ocsp_db_load_counter++;
	return 0;
}

static int test_ocsp_db_save(wget_ocsp_db *ocsp_db)
{
	(void) ocsp_db;
	return 0;
}

static const wget_ocsp_db_vtable test_ocsp_db_vtable = {
	.init = test_ocsp_db_init,
	.deinit = test_ocsp_db_deinit,
	.free = test_ocsp_db_free,
	.fingerprint_in_cache = test_ocsp_db_fingerprint_in_cache,
	.hostname_is_valid = test_ocsp_db_hostname_is_valid,
	.add_fingerprint = test_ocsp_db_add_fingerprint,
	.add_host = test_ocsp_db_add_host,
	.load = test_ocsp_db_load,
	.save = test_ocsp_db_save,
};

static void finalizer(WGET_GCC_UNUSED wget_plugin *plugin, WGET_GCC_UNUSED int exit_status)
{
	if (hpkp_db_load_counter != 1)
		wget_error_printf_exit("wget using wrong HPKP database (%d)\n", hpkp_db_load_counter);
	if (hsts_db_load_counter != 1)
		wget_error_printf_exit("wget using wrong HSTS database (%d)\n", hsts_db_load_counter);
	if (ocsp_db_load_counter != 1)
		wget_error_printf_exit("wget using wrong OCSP database (%d)\n", ocsp_db_load_counter);
}

WGET_EXPORT int wget_plugin_initializer(wget_plugin *plugin);
int wget_plugin_initializer(wget_plugin *plugin)
{
	// set the replacement for the standard HPKP database functions
	wget_hpkp_set_plugin(&test_hpkp_db_vtable);

	// set the replacement for the standard HSTS database functions
	wget_hsts_set_plugin(&test_hsts_db_vtable);

	// set the replacement for the standard OCSP database functions
	wget_ocsp_set_plugin(&test_ocsp_db_vtable);

	wget_plugin_register_finalizer(plugin, finalizer);

	return 0;
}

#else
#error One of the TEST_SELECT_* must be defined to build this file
#endif

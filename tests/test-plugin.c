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
 * Testing Wget plugin support
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

#define OBJECT_DIR "../.libs"

#if defined _WIN32
#define LOCAL_NAME(x) OBJECT_DIR "/lib" x ".dll"
#else
#define LOCAL_NAME(x) OBJECT_DIR "/lib" x ".so"
#endif

#ifdef _WIN32
#define setenv_rpl(name, value, ignored) _putenv(name "=" value)
#define unsetenv_rpl(name) _putenv(name "=")
#else
#define setenv_rpl setenv
#define unsetenv_rpl unsetenv
#endif

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body = WGET_TEST_SOME_HTML_BODY,
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	// Skip when plugin support is not available
#ifndef PLUGIN_SUPPORT
	return 77;
#endif

	wget_test_start_server
		(WGET_TEST_RESPONSE_URLS, &urls, countof(urls), 0);

	// Check whether --plugin= works
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR " --plugin=pluginname",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);

	// Check whether --local-plugin= works
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginname"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);

	// Check whether WGET2_PLUGINS works
	setenv_rpl("WGET2_PLUGIN_DIRS", OBJECT_DIR, 1);
	setenv_rpl("WGET2_PLUGINS", "pluginname", 1);
	wget_test(
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);
	unsetenv_rpl("WGET2_PLUGIN_DIRS");
	unsetenv_rpl("WGET2_PLUGINS");
	setenv_rpl("WGET2_PLUGINS", LOCAL_NAME("pluginname") , 1);
	wget_test(
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);
	unsetenv_rpl("WGET2_PLUGINS");

	// Check that --list-plugins doesn't continue
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR " --list-plugins",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// Check behavior for nonexistent plugins
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR " --plugin=nonexistent",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("nonexistent"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{	NULL } },
		0);
	setenv_rpl("WGET2_PLUGINS", LOCAL_NAME("nonexistent") , 1);
	wget_test(
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{	NULL } },
		0);
	unsetenv_rpl("WGET2_PLUGINS");

	// Check behavior for nonexistent search directories
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR "/nonexistent," OBJECT_DIR " --plugin=pluginname",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--plugin-dirs=" OBJECT_DIR "/nonexistent," OBJECT_DIR " --list-plugins",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// Check behavior for plugins that fail
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginfaulty1"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginfaulty2"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{	NULL } },
		0);

	// Check whether wget_plugin_register_finalizer works properly
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginexit"),
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "exit-status.txt", "exit(0)\n" },
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginexit"),
		WGET_TEST_REQUEST_URL, "nonexistent.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 8,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "exit-status.txt", "exit(8)\n" },
			{	NULL } },
		0);

	// Check if option forwarding works for options with no value
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.y",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "options.txt", "y\n" },
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.y "
			"--plugin-opt=pluginoption.beta",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "options.txt", "y\nbeta\n" },
			{	NULL } },
		0);

	// Check if option forwarding works with options with values
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.z= "
			"--plugin-opt=pluginoption.z=value1 --plugin-opt=pluginoption.gamma=value2",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", WGET_TEST_SOME_HTML_BODY },
			{ "options.txt", "z=\nz=value1\ngamma=value2\n" },
			{	NULL } },
		0);

	// Check behavior for incorrect format
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=.alpha=value",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.=value",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=.",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// Check behavior for incorrect plugin name
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " "
			"--plugin-opt=nonexistent.option=value",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginname") " --plugin-opt=pluginname.option=value",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "plugin-loaded.txt", "Plugin loaded\n" },
			{	NULL } },
		0);

	// Check behavior for incorrect option name/value combination
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.y=",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.y=value",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.z",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// Check for correct functioning of --help option
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-help",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.help",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);
	wget_test(
		WGET_TEST_OPTIONS, "--local-plugin=" LOCAL_NAME("pluginoption") " --plugin-opt=pluginoption.help=arg",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 1,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	exit(0);
}

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
 * Common infrastructure for testing Wget stats options.
 *
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strcmp()
#include "libtest.h"

// Runs all the "stats tests" for the given stats option.
void run_stats_test_with_option(const char *option_str);

static const char *mainpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    <a href=\"http://localhost:{{port}}/secondpage.html\">second page</a>.\n\
    <a href=\"http://localhost:{{port}}/thirdpage.html\">third page</a>.\n\
  </p>\n\
</body>\n\
</html>\n";

static const char *subpage = "\
<html>\n\
<head>\n\
  <title>Main Page</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Some text\n\
  </p>\n\
</body>\n\
</html>\n";

void run_stats_test_with_option(const char *option_str)
{
	wget_test_url_t urls[]= {
		{	.name = "/index.html", // "gnosis" in UTF-8 greek
			.code = "200 Dontcare",
			.body = mainpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body = subpage,
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/thirdpage.html",
			.code = "200 Dontcare",
			.body = subpage,
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);


	static const char *stats_format[] = {
		"human",
		"json",
		"csv",
	};

	char options[128];

	// test stats option without additional params
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, option_str,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	// test stats option without format
	snprintf(options, sizeof(options), "%s=-", option_str);
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	for (unsigned it2 = 0; it2 < countof(stats_format); it2++) {
		// test stats option with format
		snprintf(options, sizeof(options), "%s=%s:-", option_str, stats_format[it2]);
		wget_test(
			// WGET_TEST_KEEP_TMPFILES, 1,
			WGET_TEST_OPTIONS, options,
			WGET_TEST_REQUEST_URL, urls[0].name + 1,
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{ urls[0].name + 1, urls[0].body },
				{	NULL } },
			0);
	}

	for (unsigned it2 = 0; it2 < countof(stats_format); it2++) {
		// test stats option with format, With file
		if (!strcmp(option_str, "--stats-all") && !strcmp(stats_format[it2], "csv"))
			continue; // skip --stats-all=csv:stats

		snprintf(options, sizeof(options), "%s=%s:stats", option_str, stats_format[it2]);
		wget_test(
			// WGET_TEST_KEEP_TMPFILES, 1,
			WGET_TEST_OPTIONS, options,
			WGET_TEST_REQUEST_URL, urls[0].name + 1,
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{ urls[0].name + 1, urls[0].body },
				{ "stats" },
				{	NULL } },
			0);
	}

	// test stats option without additional params With -r
	snprintf(options, sizeof(options), "%s -r -nH", option_str);
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "secondpage.html", urls[1].body },
			{ "thirdpage.html", urls[2].body },
			{	NULL } },
		0);

	// test stats option without format With -r
	snprintf(options, sizeof(options), "%s=- -r -nH", option_str);
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "secondpage.html", urls[1].body },
			{ "thirdpage.html", urls[2].body },
			{	NULL } },
		0);

	for (unsigned it2 = 0; it2 < countof(stats_format); it2++) {
		// test stats option with format With -r
		snprintf(options, sizeof(options), "%s=%s:- -r -nH", option_str, stats_format[it2]);
		wget_test(
			// WGET_TEST_KEEP_TMPFILES, 1,
			WGET_TEST_OPTIONS, options,
			WGET_TEST_REQUEST_URL, urls[0].name + 1,
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{ "index.html", urls[0].body },
				{ "secondpage.html", urls[1].body },
				{ "thirdpage.html", urls[2].body },
				{	NULL } },
			0);
	}

	for (unsigned it2 = 0; it2 < countof(stats_format); it2++) {
		// test stats option with format, With file, with -r
		if (!strcmp(option_str, "--stats-all") && !strcmp(stats_format[it2], "csv"))
			continue; // skip --stats-all=csv:stats

		snprintf(options, sizeof(options), "%s=%s:stats -r -nH", option_str, stats_format[it2]);
		wget_test(
			// WGET_TEST_KEEP_TMPFILES, 1,
			WGET_TEST_OPTIONS, options,
			WGET_TEST_REQUEST_URL, urls[0].name + 1,
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{ "index.html", urls[0].body },
				{ "secondpage.html", urls[1].body },
				{ "thirdpage.html", urls[2].body },
				{ "stats" },
				{	NULL } },
			0);
	}

	// test stats-all option with csv format
	snprintf(options, sizeof(options), "%s=%s:stats", "--stats-all", "csv");
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ "0-stats" },
			{ "1-stats" },
			{ "2-stats" },
			{ "3-stats" },
			{ "4-stats" },
			{	NULL } },
		0);

	// test stats-all option with csv format with -r
	snprintf(options, sizeof(options), "%s=%s:stats -r -nH", "--stats-all", "csv");
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "secondpage.html", urls[1].body },
			{ "thirdpage.html", urls[2].body },
			{ "0-stats" },
			{ "1-stats" },
			{ "2-stats" },
			{ "3-stats" },
			{ "4-stats" },
			{	NULL } },
		0);

	// test stats-site option with tree format with -r
	snprintf(options, sizeof(options), "%s=%s:stats -r -nH", "--stats-site", "tree");
	wget_test(
		// WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, options,
		WGET_TEST_REQUEST_URL, urls[0].name + 1,
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ "secondpage.html", urls[1].body },
			{ "thirdpage.html", urls[2].body },
			{ "stats" },
			{	NULL } },
		0);


}

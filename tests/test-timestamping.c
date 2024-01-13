/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // strlen()
#include "libtest.h"

/* test for -N (--timestamping) and --no-if-modified-since */

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/dummy.txt",
			.code = "200 Dontcare",
			.body = "Don't care.",
			.headers = {
				"Content-Type: text/plain",
			},
		},
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body = "<a href=\"a.html\">link</a>",
			.headers = {
				"Content-Type: text/html",
			},
		},
		{	.name = "/dummy2.txt",
			.code = "200 Dontcare",
			.body = "Don't care2.",
			.headers = {
				"Content-Type: text/plain",
			},
		},
		{	.name = "/a.html",
			.code = "200 Dontcare",
			.body = "<a href=\"dummy.txt\">link</a>",
			.headers = {
				"Content-Type: text/html",
			},
		},
		{	.name = "/b.html",
			.code = "200 Dontcare",
			.body = "<a href=\"dummy2.txt\">link</a>",
			.headers = {
				"Content-Type: text/html",
			},
		},
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	for (unsigned i = 0; i < countof(urls); i++)
		urls[i].headers[1] = "Last-Modified: Sat, 09 Oct 2004 08:30:00 GMT";

	// test-N--no-content-disposition-trivial
	wget_test(
		WGET_TEST_OPTIONS, "-N --no-content-disposition",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	urls[0].headers[2] = "Content-Disposition: attachment; filename=\"filename.txt\"";

	// test-N--no-content-disposition
	wget_test(
		WGET_TEST_OPTIONS, "-N --no-content-disposition",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	// test-N-HTTP--content-disposition
	wget_test(
		WGET_TEST_OPTIONS, "-N --content-disposition",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"filename.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	urls[0].headers[2] = NULL;

	{
		// server sends same length content with slightly different content
		char *modified = wget_strdup(urls[0].body);
		modified[3] = 'x';

		urls[0].modified = 1097310600;

		// test-N-current
		wget_test(
			WGET_TEST_OPTIONS, "-N",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
			0);

		// test-N-old
		wget_test(
			WGET_TEST_OPTIONS, "-N",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310000 }, // earlier timestamp
				{	NULL } },
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", urls[0].body, 1097310600 },
				{	NULL } },
			0);

		// test-N-old without If-Modified-Since
		wget_test(
			WGET_TEST_OPTIONS, "-N --no-if-modified-since",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310000 }, // earlier timestamp
				{	NULL } },
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", urls[0].body, 1097310600 },
				{	NULL } },
			0);

		// test wget2 won't download the file if timestamp and size of local file are OK
		wget_test(
			WGET_TEST_OPTIONS, "-N --no-if-modified-since",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
			0);

		// test -N --no-if-modified-since --filter-mime-type
		wget_test(
			WGET_TEST_OPTIONS, "-N --no-if-modified-since --filter-mime-type=text/plain",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
				WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
			0);

		// test -N --no-if-modified-since --chunk-size
		// if size and timestamp match do nothing
		wget_test(
			WGET_TEST_OPTIONS, "-N --no-if-modified-since --chunk-size=2",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
				WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
			0);

		// This test just works with a HEAD request
		const char *old_body = urls[0].body;
		modified[strlen(modified)-2] = 0;
		urls[0].body = modified;
		wget_test(
			WGET_TEST_OPTIONS, "-N --no-if-modified-since",
			WGET_TEST_REQUEST_URL, "dummy.txt",
			WGET_TEST_EXPECTED_ERROR_CODE, 0,
			WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", old_body, 1097310600 },
				{	NULL } },
			WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
				{	"dummy.txt", modified, 1097310600 },
				{	NULL } },
			0);
		urls[0].body = old_body; // restore body
		wget_xfree(modified);
	}

	// test-N
	wget_test(
		WGET_TEST_OPTIONS, "-N",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 0},
			{	NULL } },
		0);

	//urls[0].headers[1] = NULL;

	// test-N-no-info (sizes do not match)
	// This test just works with a HEAD request
	wget_test(
		WGET_TEST_OPTIONS, "-N --no-if-modified-since",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", "anycontent", 1097310600 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 0},
			{	NULL } },
		0);

	// tests in combination with --filter-mime-type
	wget_test(
		WGET_TEST_OPTIONS, "-N --no-if-modified-since --filter-mime-type \"*,!text/plain\"",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-N --no-if-modified-since --filter-mime-type=text/plain",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-N --no-if-modified-since --filter-mime-type=text/plain",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", "anycontent", 1097310600 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-N --no-if-modified-since --filter-mime-type=text/plain",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310000 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	// tests in combination with --chunk-size
	wget_test(
		WGET_TEST_OPTIONS, "-N --no-if-modified-since --chunk-size=2",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	// chunk bigger than dummy.txt length
	wget_test(
		WGET_TEST_OPTIONS, "-N --no-if-modified-since --chunk-size=20",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", "anycontent", 1097310600 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	// chunk smaller than dummy.txt length
/*	wget_test(
		WGET_TEST_KEEP_TMPFILES, 1,
		WGET_TEST_OPTIONS, "--chunk-size=2",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", "anycontent", 1097310600 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);*/

	// this test is also broken if chunk-size < file length (e.g. chunk-size=2)
	wget_test(
		WGET_TEST_OPTIONS, "-N --no-if-modified-since --chunk-size=20",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310000 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	// tests in combination with -r
	urls[1].modified = 1097310600;
	const char *modified2 = "<a href=\"dummy.txt\">link</a>";
	wget_test(
		WGET_TEST_OPTIONS, "-N -r -nd",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"index.html", modified2, 1097310600 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"index.html", modified2, 1097310600 },
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-N -r -nd",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	"index.html", modified2, 1097310000 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	"index.html", urls[1].body, 1097310600 },
			{	urls[3].name + 1, urls[3].body, 1097310600 },
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r -nH -N --no-if-modified-since",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	urls[1].name + 1, urls[1].body, 1097310600 },
			{	urls[3].name + 1, urls[3].body, 1097310600 },
			{	"dummy.txt", urls[0].body, 1097310600 },
			{	NULL } },
		0);

	// -N --no-if-modified-since should have the same behavior as only -N
	// (except for size comparison)
	const char *modified = "<a href=\"b.html\">link</a>";
	wget_test(
		WGET_TEST_OPTIONS, "-N -r -nd --no-if-modified-since",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{	urls[1].name + 1, modified, 1097310600 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	urls[1].name + 1, modified, 1097310600 },
			{	urls[4].name + 1, urls[4].body, 1097310600 },
			{	urls[2].name + 1, urls[2].body, 1097310600 },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}

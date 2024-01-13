/*
 * Copyright (c) 2018-2024 Free Software Foundation, Inc.
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
 */

#include <config.h>

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <A hreF=\"http://localhost:{{port}}/secondpage.html\">second page</a>." \
				" <a href=\"picture_a.jpeg\">Picture a</a>." \
				" <a href=\"picture_aa.jpeg\">Picture aa</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body><p>A link to a" \
				" <a href=\"picture_b.jpeg\">Picture b</a>." \
				" <a href=\"picture_bb.JpeG\">Picture bb</a>." \
				" <a href=\"picture_c.png\">Picture c</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/picture_a.jpeg",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/picture_aa.jpeg",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/picture_b.jpeg",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/picture_bb.JpeG",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/picture_c.png",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/png" }
		},
                {       .name = "/dummy.txt",
                        .code = "200 Dontcare",
                        .body = "What ever"
                }
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		0);

	// only want image/png
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"image/png\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// don't want image/png
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"*,!image/png\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// only want png using wildcards
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"*/png\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// don't want png using wildcards
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"*,!*/png\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// only want png and jpeg using wildcards
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"*/png,*/jpeg\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// don't want png but want jpeg using wildcards
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"!*/png,*/jpeg\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// only want png using wildcards
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"image/*,!*/jpeg\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// simple --filter-mime-type tests
	wget_test(
		WGET_TEST_OPTIONS, "--filter-mime-type text/html",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--filter-mime-type \"*,!text/html\"",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// As dummy.txt hasn't MIME type is considered to be 'application/octet-stream' (RFC 7231, sec. 3.1.1.5)
	wget_test(
		WGET_TEST_OPTIONS, "--filter-mime-type \"*,!text/plain\"",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[7].name + 1, urls[7].body },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--filter-mime-type \"text/plain\"",
		WGET_TEST_REQUEST_URL, "dummy.txt",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{	NULL } },
		0);

	// tests with -N --no-if-modified-since
	for (unsigned i = 0; i < countof(urls); i++) {
		urls[i].headers[1] = "Last-Modified: Sat, 09 Oct 2004 08:30:00 GMT";
	}
	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"image/*,!*/jpeg\" -N --no-if-modified-since",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[6].name + 1, urls[6].body, 1097310600 },
			{	NULL } },
		0);

	wget_test(
		WGET_TEST_OPTIONS, "-r -nH --filter-mime-type \"image/*,!*/jpeg\" -N --no-if-modified-since",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body, 1097310900 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body, 1097310900 },
			{ urls[6].name + 1, urls[6].body, 1097310600 },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}

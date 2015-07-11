/*
 * Copyright(c) 2013 Tim Ruehsen
 *
 * This file is part of libmget.
 *
 * Libmget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libmget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libmget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Testing Mget
 *
 * Changelog
 * 08.07.2013  Tim Ruehsen  created
 * 02.07.2014  Tim Ruehsen  added uppercase combinations of <a href...> (issue #21)
 *
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	mget_test_url_t urls[]={
		{	.name = "/index.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Main Page</title></head><body><p>A link to a" \
				" <A hreF=\"http://localhost:{{port}}/secondpage.html\">second page</a>." \
				" <a href=\"picture_a.jpeg\">Picture a</a>." \
				" <a href=\"picture_A.jpeg\">Picture A</a>." \
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
				" <a href=\"picture_B.JpeG\">Picture B</a>." \
				" <a href=\"picture_c.png\">Picture C</a>." \
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
		{	.name = "/picture_A.jpeg",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/picture_b.jpeg",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/picture_B.JpeG",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/picture_c.png",
			.code = "200 Dontcare",
			.body = "don't care",
			.headers = { "Content-Type: image/png" }
		},
	};

	// functions won't come back if an error occurs
	mget_test_start_server(
		MGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	// --accept using just suffixes
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --accept '.jpeg'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{	NULL } },
		0);

	// --reject using just suffixes
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --reject '.jpeg'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// --accept using just suffixes and ignore case
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --accept '.jpeg' --ignore-case",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// --reject using just suffixes and ignore case
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --reject '.jpeg' --ignore-case",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// --accept using wildcards
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --accept '*.jpeg'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{	NULL } },
		0);

	// --reject using wildcards
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --reject '*.jpeg'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// --accept using wildcards and ignore case
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --accept '*.jpeg' --ignore-case",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// --reject using wildcards and ignore case
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --reject '*.jpeg' --ignore-case",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// --accept using wildcards
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --accept '*picture*'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// --reject using wildcards
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --reject '*picture*'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{	NULL } },
		0);

	// --accept using wildcards
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --accept '*picture_[ab]*'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[4].name + 1, urls[4].body },
			{	NULL } },
		0);

	// --reject using wildcards
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --reject '*picture_[ab]*'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[5].name + 1, urls[5].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// --accept using wildcards
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --accept '*picture_a*' --accept '*picture_c*'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[2].name + 1, urls[2].body },
			{ urls[6].name + 1, urls[6].body },
			{	NULL } },
		0);

	// --reject using wildcards
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --reject '*picture_a*' --reject '*picture_c*'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	exit(0);
}

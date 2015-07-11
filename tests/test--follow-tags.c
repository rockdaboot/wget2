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
 * 09.09.2014  Tim Ruehsen  created
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
				" <a href=\"secondpage.html\">second page</a>." \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/secondpage.html",
			.code = "200 Dontcare",
			.body =
				"<html><head><title>Second Page</title></head><body><p>A link to a" \
				" <a href=\"2a.jpeg\">Picture 2a</a>." \
				" <img src=\"2b.jpeg\" data-500px=\"2c.jpeg\" data-highres=\"2d.jpeg\">" \
				"</p></body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		},
		{	.name = "/2a.jpeg",
			.code = "200 Dontcare",
			.body = "pic 2a",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/2b.jpeg",
			.code = "200 Dontcare",
			.body = "pic 2b",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/2c.jpeg",
			.code = "200 Dontcare",
			.body = "pic 2c",
			.headers = { "Content-Type: image/jpeg" }
		},
		{	.name = "/2d.jpeg",
			.code = "200 Dontcare",
			.body = "pic 2c",
			.headers = { "Content-Type: image/jpeg" }
		},
	};

	// functions won't come back if an error occurs
	mget_test_start_server(
		MGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		0);

	// without additional tags
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH ",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{	NULL } },
		0);

	// --follow-tags single entry
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --follow-tags 'img/data-500px'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{	NULL } },
		0);

	// --follow-tags single entry without attribute
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --follow-tags 'img'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// --follow-tags two entries
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --follow-tags 'img/data-500px,img/data-highres'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// --follow-tags two entries
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --follow-tags 'img/data-highres,img/data-500px'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[3].name + 1, urls[3].body },
			{ urls[4].name + 1, urls[4].body },
			{ urls[5].name + 1, urls[5].body },
			{	NULL } },
		0);

	// --ignore-tags single entry
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --ignore-tags 'img/src'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);

	// --ignore-tags single entry without attribute
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --ignore-tags 'img'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{	NULL } },
		0);

	// --ignore-tags two entries
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --ignore-tags 'img/src,a/href'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	// --ignore-tags two entries
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --ignore-tags 'a/href,img/src'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{	NULL } },
		0);

	// --ignore-tags and --follow-tags combined
	mget_test(
		MGET_TEST_OPTIONS, "-r -nH --ignore-tags 'img/src' --follow-tags='img/data-500px'",
		MGET_TEST_REQUEST_URL, "index.html",
		MGET_TEST_EXPECTED_ERROR_CODE, 0,
		MGET_TEST_EXPECTED_FILES, &(mget_test_file_t []) {
			{ urls[0].name + 1, urls[0].body },
			{ urls[1].name + 1, urls[1].body },
			{ urls[2].name + 1, urls[2].body },
			{ urls[4].name + 1, urls[4].body },
			{	NULL } },
		0);

	exit(0);
}

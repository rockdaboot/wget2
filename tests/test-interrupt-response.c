/*
 * Copyright (c) 2020-2024 Free Software Foundation, Inc.
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
 * Tests interruptions to responses received by wget and continuing afterwards
 */

#include <config.h>

#include <stdlib.h> // exit()
#include <string.h> // memset()
#include "libtest.h"

#define DUMMYDATA_SIZE 1024
#define INTERRUPT_AFTER_NBYTES 512

int main(void)
{
	static char data1[DUMMYDATA_SIZE + 1];
	memset(data1, '@', sizeof(data1) - 1);

	static char data2[DUMMYDATA_SIZE + 1];
	memset(data2, '-', sizeof(data2) - 1);

	static char data1_interrupted[INTERRUPT_AFTER_NBYTES + 1];
	memset(data1_interrupted, '@', sizeof(data1_interrupted) - 1);

	static char data12_merged[DUMMYDATA_SIZE + 1];
	memcpy(data12_merged, data1, INTERRUPT_AFTER_NBYTES);
	memcpy(data12_merged + INTERRUPT_AFTER_NBYTES, data2, INTERRUPT_AFTER_NBYTES);


	wget_test_url_t urls[]={
		{	.name = "/file1.bin",
			.code = "200 Dontcare",
			.body = data1,
			.headers = {
				"Content-Type: application/octet-stream",
			},
			.interrupt_response_mode = INTERRUPT_RESPONSE_DISABLED
		},
		{	.name = "/file2.bin",
			.code = "200 Dontcare",
			.body = data1,
			.headers = {
				"Content-Type: application/octet-stream",
			},
			.interrupt_response_mode = INTERRUPT_RESPONSE_DURING_BODY,
			.interrupt_response_after_nbytes = 0
		},
		{	.name = "/file3.bin",
			.code = "200 Dontcare",
			.body = data1,
			.headers = {
				"Content-Type: application/octet-stream",
			},
			.interrupt_response_mode = INTERRUPT_RESPONSE_DURING_BODY,
			.interrupt_response_after_nbytes = INTERRUPT_AFTER_NBYTES
		},
		{	.name = "/file4.bin",
			.code = "200 Dontcare",
			.modified = 1000000000,
			.body = data1,
			.headers = {
				"Content-Type: application/octet-stream",
				"Last-Modified: Sun, 09 Sep 2001 01:46:40 GMT", // =1000000000
			},
			.interrupt_response_mode = INTERRUPT_RESPONSE_DURING_BODY,
			.interrupt_response_after_nbytes = INTERRUPT_AFTER_NBYTES
		}
	};

	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_FEATURE_MHD,
		WGET_TEST_SKIP_H2,
		0);

	// Test interrupt request disabled
	wget_test(
		WGET_TEST_OPTIONS, "",
		WGET_TEST_REQUEST_URL, "file1.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file1.bin", data1 },
			{	NULL } },
		0);

	// Test interrupt connection immediately
	wget_test(
		WGET_TEST_OPTIONS, "--tries=2",
		WGET_TEST_REQUEST_URL, "file2.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 7,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file2.bin", "" },
			{	NULL } },
		0);

	// test interrupting connection during headers transfer
	wget_test(
//		WGET_TEST_EXECUTABLE, "/usr/bin/wget",
		WGET_TEST_OPTIONS, "--tries=2",
		WGET_TEST_REQUEST_URL, "file3.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 7,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file3.bin", data1_interrupted },
			{	NULL } },
		0);

	// disable the interrupt response mode to test continue
	urls[2].interrupt_response_mode = INTERRUPT_RESPONSE_DISABLED;
	urls[2].body = data2;

	// test continue after interrupt
	// Wget1.x fails here
	wget_test(
//		WGET_TEST_EXECUTABLE, "/usr/bin/wget -d",
		WGET_TEST_OPTIONS, "-c --tries=2",
		WGET_TEST_REQUEST_URL, "file3.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "file3.bin", data1_interrupted },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file3.bin", data12_merged },
			{	NULL } },
		0);

	// Testing interrupting responses while timestamping is active
	// Expect that timestamp of partially finished file will match server minus one due to interruption
	// Wget1.x leaves the partial file with a current timestamp (ignoring Last-Modified header)
	wget_test(
//		WGET_TEST_EXECUTABLE, "/usr/bin/wget",
		WGET_TEST_OPTIONS, "-N --tries=2",
		WGET_TEST_REQUEST_URL, "file4.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 7,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file4.bin", data1_interrupted, 1000000000 - 1 },
			{	NULL } },
		0);

	// disable the interrupt response mode to test continue
	urls[3].interrupt_response_mode = INTERRUPT_RESPONSE_DISABLED;
	urls[3].body = data2;

	// Testing continue interrupted response while timestamping is active
	// Expect that file will be skipped due to "304 not modified" from server
	wget_test(
//		WGET_TEST_EXECUTABLE, "/usr/bin/wget",
		WGET_TEST_OPTIONS, "-c -N",
		WGET_TEST_REQUEST_URL, "file4.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "file4.bin", data1_interrupted, 1000000000 },
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file4.bin", data1_interrupted, 1000000000 },
			{	NULL } },
		0);

	// Testing continue interrupted response while timestamping is active
	// Expect that file will be appended/merged due to "206 Partial Content" from server
	wget_test(
//		WGET_TEST_EXECUTABLE, "/usr/bin/wget",
		WGET_TEST_OPTIONS, "-c -N",
		WGET_TEST_REQUEST_URL, "file4.bin",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXISTING_FILES, &(wget_test_file_t []) {
			{ "file4.bin", data1_interrupted, 1000000000 - 1 }, // 1s older than on server
			{	NULL } },
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "file4.bin", data12_merged, 1000000000 },
			{	NULL } },
		0);

	exit(EXIT_SUCCESS);
}

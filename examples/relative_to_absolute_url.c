/*
 * Copyright (c) 2019-2024 Free Software Foundation, Inc.
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
 * Demonstrate how to convert relative URLs into absolute URLs.
 */

#include <stdio.h> // printf
#include <string.h> // strlen
#include <wget.h>

int main(void)
{
	const char *base_url = "https://example.com/subdir1/";
	const char *relative_url;
	const char *absolute_url;

	wget_iri *base = wget_iri_parse(base_url, NULL);
	wget_buffer *buf = wget_buffer_alloc(128); // initial size is 128, but automatically grows larger if needed

	relative_url = "x.png";
	absolute_url = wget_iri_relative_to_abs(base, relative_url, -1, buf);
	printf("%s + %s -> %s\n", base_url, relative_url, absolute_url);

	relative_url = "../x.png";
	absolute_url = wget_iri_relative_to_abs(base, relative_url, -1, buf);
	printf("%s + %s -> %s\n", base_url, relative_url, absolute_url);

	// show that this is handled gracefully
	relative_url = "../../x.png";
	absolute_url = wget_iri_relative_to_abs(base, relative_url, -1, buf);
	printf("%s + %s -> %s\n", base_url, relative_url, absolute_url);

	relative_url = "subdir2/x.png";
	absolute_url = wget_iri_relative_to_abs(base, relative_url, -1, buf);
	printf("%s + %s -> %s\n", base_url, relative_url, absolute_url);

	relative_url = "/x.png";
	absolute_url = wget_iri_relative_to_abs(base, relative_url, -1, buf);
	printf("%s + %s -> %s\n", base_url, relative_url, absolute_url);

	// clean up before going out of scope
	wget_buffer_free(&buf);
	wget_iri_free(&base);

	return 0;
}

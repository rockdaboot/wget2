/*
 * Copyright (c) 2025-2026 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
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
 * You should have received a GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Unit tests for wget_html_get_urls_inline()
 *
 * Tests URL extraction from HTML including:
 * - iframe srcdoc attribute (HTML parsing of srcdoc content)
 * - XML entity decoding in srcdoc content
 * - Regular href/src URL extraction
 * - Base tag handling
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wget.h>
#include "../libwget/private.h"
#include "../src/wget_options.h"

static int
	ok,
	failed;

static void check(int result, int line, const char *msg)
{
	if (result) {
		ok++;
	} else {
		failed++;
		wget_info_printf("L%d: %s\n", line, msg);
	}
}

#define CHECK(e) check(!!(e), __LINE__, #e)

/**
 * Count the number of URIs in a parsed result.
 */
static int count_uris(const wget_html_parsed_result *res)
{
	if (!res || !res->uris)
		return 0;
	return wget_vector_size(res->uris);
}

/**
 * Check that a parsed result contains a URL with the expected tag/attr/value.
 */
static void check_url(const wget_html_parsed_result *res, const char *tag, const char *attr, const char *expected_value)
{
	CHECK(res != NULL);
	if (!res || !res->uris) {
		failed++;
		wget_info_printf("  no URIs found\n");
		return;
	}
	int found = 0;
	for (int i = 0; i < wget_vector_size(res->uris); i++) {
		wget_html_parsed_url *url = wget_vector_get(res->uris, i);
		if (url && !strcmp(url->tag, tag) && !strcmp(url->attr, attr)) {
			if (expected_value == NULL) {
				found = 1;
			} else {
				if (strlen(expected_value) == url->url.len && !memcmp(expected_value, url->url.p, url->url.len)) {
					found = 1;
				} else {
					wget_info_printf("  got '%.*s' (len=%zu) expected '%s'\n", (int) url->url.len, url->url.p, url->url.len, expected_value);
				}
			}
		}
	}
	CHECK(found);
}

static void test_iframe_srcdoc_basic(void)
{
	const char *html =
		"<html><body>\n"
		"<iframe srcdoc=\"<a href='inner.html'>link</a>\"></iframe>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);

	// Should have 1 URL from srcdoc content
	CHECK(n == 1);
	check_url(res, "a", "href", "inner.html");

	wget_html_free_urls_inline(&res);
}

static void test_iframe_srcdoc_with_entities(void)
{
	// Test that XML entities in srcdoc are decoded and the inner HTML is parsed
	const char *html =
		"<html><body>\n"
		"<iframe srcdoc=\"&lt;a href='&amp;page=1'&gt;link&lt;/a&gt;\"></iframe>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);
	wget_info_printf("iframe srcdoc with entities: %d URIs\n", n);
	// Should have 1 URL from srcdoc content, with decoded entities
	CHECK(n == 1);
	check_url(res, "a", "href", "&page=1");

	wget_html_free_urls_inline(&res);
}

static void test_iframe_srcdoc_multiple_urls(void)
{
	// Test multiple URLs inside srcdoc content
	const char *html =
		"<html><body>\n"
		"<iframe srcdoc=\"<a href='a.html'>a</a><a href='b.html'>b</a><img src='pic.png'\"></iframe>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);
	wget_info_printf("iframe srcdoc multiple URLs: %d URIs\n", n);
	// Should have 3 URLs from srcdoc content (2 href + 1 src)
	CHECK(n == 3);
	check_url(res, "a", "href", "a.html");
	check_url(res, "a", "href", "b.html");
	check_url(res, "img", "src", "pic.png");

	wget_html_free_urls_inline(&res);
}

static void test_iframe_srcdoc_with_regular_urls(void)
{
	// Test that URLs from both regular HTML and srcdoc are collected
	const char *html =
		"<html><body>\n"
		"<a href='outer.html'>outer</a>\n"
		"<iframe srcdoc=\"<a href='inner.html'>inner</a>\"></iframe>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);
	wget_info_printf("iframe srcdoc + regular: %d URIs\n", n);
	// Should have 2 URLs: 1 from regular HTML + 1 from srcdoc
	CHECK(n == 2);
	check_url(res, "a", "href", "outer.html");
	check_url(res, "a", "href", "inner.html");

	wget_html_free_urls_inline(&res);
}

static void test_iframe_srcdoc_with_base(void)
{
	// Test that BASE tag in srcdoc does not affect outer URL resolution
	// (BASE is stored but srcdoc URLs are extracted as-is)
	const char *html =
		"<html><body>\n"
		"<base href='https://example.com/'>\n"
		"<iframe srcdoc=\"<a href='inner.html'></a>\"></iframe>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);
	CHECK(res->base.p != NULL);
	CHECK(memcmp(res->base.p, "https://example.com/", res->base.len) == 0);

	int n = count_uris(res);
	wget_info_printf("iframe srcdoc with base: %d URIs\n", n);
	CHECK(n == 1);
	check_url(res, "a", "href", "inner.html");

	wget_html_free_urls_inline(&res);
}

static void test_iframe_srcdoc_empty(void)
{
	// Test empty srcdoc attribute
	const char *html =
		"<html><body>\n"
		"<iframe srcdoc=\"\"></iframe>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);
	wget_info_printf("iframe srcdoc empty: %d URIs\n", n);
	// Empty srcdoc should produce no URLs
	CHECK(n == 0);

	wget_html_free_urls_inline(&res);
}

static void test_iframe_srcdoc_with_xml_entities(void)
{
	// Test various XML entity decodings in srcdoc
	const char *html =
		"<html><body>\n"
		"<iframe srcdoc=\"&lt;img src='&quot;test.png&quot;'&gt;\"></iframe>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);
	wget_info_printf("iframe srcdoc with quot entity: %d URIs\n", n);
	// Should decode &quot; to " and extract the URL
	CHECK(n == 1);
	check_url(res, "img", "src", "\"test.png\"");

	wget_html_free_urls_inline(&res);
}

static void test_iframe_srcdoc_nested_tags(void)
{
	// Test nested HTML tags inside srcdoc
	const char *html =
		"<html><body>\n"
		"<iframe srcdoc=\"<div><a href='nested.html'>link</a></div>\"></iframe>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);
	wget_info_printf("iframe srcdoc nested: %d URIs\n", n);
	CHECK(n == 1);
	check_url(res, "a", "href", "nested.html");

	wget_html_free_urls_inline(&res);
}

static void test_regular_href_extraction(void)
{
	// Regression: ensure regular href extraction still works
	const char *html =
		"<html><body>\n"
		"<a href='page.html'>link</a>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);
	CHECK(n == 1);
	check_url(res, "a", "href", "page.html");

	wget_html_free_urls_inline(&res);
}

static void test_regular_src_extraction(void)
{
	// Regression: ensure regular src extraction still works
	const char *html =
		"<html><body>\n"
		"<img src='image.png'>\n"
		"</body></html>";

	wget_html_parsed_result *res = wget_html_get_urls_inline(html, NULL, NULL);
	CHECK(res != NULL);

	int n = count_uris(res);
	CHECK(n == 1);
	check_url(res, "img", "src", "image.png");

	wget_html_free_urls_inline(&res);
}

int main(int argc, const char **argv)
{
	if (init(argc, argv) < 0)
		return -1;

	wget_info_printf("=== iframe srcdoc tests ===\n");
	test_iframe_srcdoc_basic();
	test_iframe_srcdoc_with_entities();
	test_iframe_srcdoc_multiple_urls();
	test_iframe_srcdoc_with_regular_urls();
	test_iframe_srcdoc_with_base();
	test_iframe_srcdoc_empty();
	test_iframe_srcdoc_with_xml_entities();
	test_iframe_srcdoc_nested_tags();

	wget_info_printf("=== regression tests ===\n");
	test_regular_href_extraction();
	test_regular_src_extraction();

	deinit();

	if (failed) {
		wget_info_printf("Summary: %d out of %d tests failed\n", failed, ok + failed);
		return 1;
	}

	wget_info_printf("Summary: All %d tests passed\n", ok + failed);
	return 0;
}

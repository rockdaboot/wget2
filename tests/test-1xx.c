#include <config.h>
#include <stdlib.h> // exit()
#include "libtest.h"

int main(void)
{
	wget_test_url_t urls[] = {
		{
			.name = "/index.html",
			.code = "200 OK",
			.code_1xx = "103",
			.body = "<html><body>Hello World</body></html>",
			.headers = {
				"Content-Type: text/html",
			}
		}
	};

	// functions won't come back if an error occurs
	wget_test_start_server(
		WGET_TEST_RESPONSE_URLS, &urls, countof(urls),
		WGET_TEST_H2_ONLY,
		0);

	wget_test(
		WGET_TEST_OPTIONS, "--no-check-certificate",
		WGET_TEST_REQUEST_URL, "index.html",
		WGET_TEST_EXPECTED_ERROR_CODE, 0,
		WGET_TEST_EXPECTED_FILES, &(wget_test_file_t []) {
			{ "index.html", urls[0].body },
			{ NULL } },
		0);

	exit(EXIT_SUCCESS);
}

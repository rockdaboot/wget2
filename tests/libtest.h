/* 
 * File:   libtest.h
 * Author: tim
 *
 * Created on 10. März 2013, 20:21
 */

#ifndef _LIBMGET_LIBTEST_H
#define _LIBMGET_LIBTEST_H

#include <libmget.h>

#ifdef	__cplusplus
extern "C" {
#endif

// defines for mget_test_start_http_server()
#define MGET_TEST_EXPECTED_REQUEST_HEADER 1001
#define MGET_TEST_RESPONSE_URLS 1002

// defines for mget_test()
#define MGET_TEST_REQUEST_URL 2001
#define MGET_TEST_OPTIONS 2002
#define MGET_TEST_EXPECTED_ERROR_CODE 2003
#define MGET_TEST_EXPECTED_FILES 2004
#define MGET_TEST_EXISTING_FILES 2005
#define MGET_TEST_KEEP_TMPFILES 2006

#define countof(a) (sizeof(a)/sizeof(*(a)))

G_GNUC_MGET_UNUSED static const char *MGET_TEST_SOME_HTML_BODY = "\
<html>\n\
<head>\n\
  <title>The Title</title>\n\
</head>\n\
<body>\n\
  <p>\n\
    Some text\n\
  </p>\n\
</body>\n\
</html>\n";

typedef struct {
	const char *
		name;
	const char *
		content;
	time_t
		timestamp;
} mget_test_file_t;

typedef struct {
	const char *
		name;
	const char *
		code;
	const char *
		body;
	const char *
		headers[10];
	char
		body_alloc; // if body has been allocated internally (and need to be freed on exit)
} mget_test_url_t;

void mget_test_stop_http_server(void);
void mget_test_start_http_server(int first_key, ...);
void mget_test(int first_key, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBMGET_LIBTEST_H */

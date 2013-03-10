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
#define MGET_TEST_RESPONSE_BODY 1001
#define MGET_TEST_RESPONSE_HEADER 1002
#define MGET_TEST_EXPECTED_REQUEST_HEADER 1003
#define MGET_TEST_RESPONSE_CODE 1004

// defines for mget_test()
#define MGET_TEST_NAME 2001
#define MGET_TEST_REQUEST_URL 2002
#define MGET_TEST_OPTIONS 2003
#define MGET_TEST_EXPECTED_ERROR_CODE 2004
#define MGET_TEST_EXPECTED_FILE 2005
#define MGET_TEST_EXPECTED_FILE_CONTENT 2006

void mget_test_stop_http_server(void);
void mget_test_start_http_server(int first_key, ...);
void mget_test(int first_key, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBMGET_LIBTEST_H */

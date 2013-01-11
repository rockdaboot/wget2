// just a test for static linking

#include <libmget.h>
//#include "http.h"

int main(void)
{
//	HTTP_REQUEST req;

//	http_get(http_open(iri_parse("www.example.com",NULL)), &req);
	mget_vector_size(NULL);
	mget_buffer_alloc(0);
	mget_buffer_printf((mget_buffer_t *)1,"%s","");
	mget_base64_is_string("");
}

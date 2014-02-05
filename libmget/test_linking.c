// Just a test for static linking.
// We call one function from each object file in libmget.
// Unresolved references should come up on linking.

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h> // CygWin strlcpy() declaration
#include <libmget.h>

int main(void)
{
	char *empty = (char *)"";

	mget_info_printf("%d\n", mget_base64_is_string("")); // base64.c
	mget_buffer_alloc(0); // buffer.c
	mget_buffer_printf((mget_buffer_t *)1, "%s", ""); // buffer_printf.c
	strlcpy((char *)"", "", 0); // compat.c
	mget_cookie_free_public_suffixes(); // cookie.c
	mget_css_parse_buffer((const char *)1, NULL, NULL, NULL); // css.c
	mget_decompress_close(NULL); // decompressor.c
	mget_hashmap_create(0, 0, NULL, NULL); // hashmap.c
	mget_fdgetline(&empty, (size_t *)1, 0); // io.c
	mget_iri_parse("", NULL); // iri.c
	mget_list_free((mget_list_t **)1); // list.c
	mget_debug_write("", 0); // log.c
	mget_logger_set_file(NULL, ""); // logger.c
	mget_tcp_set_connect_timeout(NULL, 0); // net.c
	mget_strdup(""); // mem.c
	mget_popenf("r", "%s", ""); // pipe.c
	mget_bsprintf(NULL, NULL, "%s", ""); // printf.c
	mget_ssl_set_config_int(0, 0); // ssl_[gnutls].c
	mget_stringmap_create(0); // stringmap.c
	if (mget_strcmp("", "")) {}; // utils.c
	mget_vector_set_destructor(NULL, NULL); // vector.c
	mget_malloc(1); // xalloc.c
	mget_xml_parse_buffer("", NULL, NULL, 0); // xml.c
}

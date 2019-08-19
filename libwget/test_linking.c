// Just a test for static linking.
// We call one function from each object file in libwget.
// Unresolved references should come up on linking.

#include <config.h>

#include <string.h> // CygWin strlcpy() declaration
#include <wget.h>

int main(void)
{
	char *empty = (char *)"";
	char buf[1];

	wget_info_printf("%d\n", wget_base64_is_string("")); // base64.c
	wget_buffer *bufp = wget_buffer_alloc(1); // buffer.c
	wget_buffer_free(&bufp);
	wget_buffer_printf((wget_buffer *)1, "%s", ""); // buffer_printf.c
	wget_strlcpy(buf, "", 0); // strlcpy.c
	wget_strscpy(buf, "", 0); // strscpy.c
	wget_css_parse_buffer((const char *)1, 0, NULL, NULL, NULL); // css.c
	wget_decompress_close(NULL); // decompressor.c
	wget_hashmap_create(0, NULL, NULL); // hashmap.c
	wget_fdgetline(&empty, (size_t *)1, 0); // io.c
	wget_iri_parse("", NULL); // iri.c
	wget_list_free((wget_list **)1); // list.c
	wget_debug_write("", 0); // log.c
	wget_logger_set_file(NULL, ""); // logger.c
	wget_tcp_set_connect_timeout(NULL, 0); // net.c
	wget_netrc_deinit(NULL); // netrc.c
	wget_free(wget_strdup("")); // mem.c
//	wget_popenf("r", "%s", ""); // pipe.c
//	wget_bsprintf(NULL, NULL, "%s", ""); // printf.c
	wget_ssl_set_config_int(0, 0); // ssl_[gnutls].c
	wget_stringmap_create(0); // stringmap.c
	if (wget_strcmp("", "")) {} // utils.c
	wget_vector_set_destructor(NULL, NULL); // vector.c
	wget_free(wget_malloc(1)); // xalloc.c
	wget_xml_parse_buffer("", NULL, NULL, 0); // xml.c
	wget_plugin_get_name((wget_plugin *) 1); // plugin.c
}

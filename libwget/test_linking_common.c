// Just a test for static linking.
// We call one function from each object file in libwget_common
// Unresolved references should come up on linking.

#include <config.h>
#include <wget.h>

int main(void)
{
	char buf[1];

	wget_info_printf("%d\n", wget_base64_is_string("")); // base64.c
	wget_buffer *buffer = wget_buffer_alloc(1); // buffer.c
	wget_buffer_free(&buffer);
	wget_buffer_printf((wget_buffer *)1, "%s", ""); // buffer_printf.c
	wget_strlcpy(buf, "", 0); // strlcpy.c
	wget_strscpy(buf, "", 0); // strscpy.c
	wget_hashmap_create(0, NULL, NULL); // hashmap.c
	wget_list_free((wget_list **)1); // list.c
	wget_debug_write("", 0); // log.c
	wget_free(wget_strdup("")); // mem.c
	wget_stringmap_create(0); // stringmap.c
	if (wget_strcmp("", "")) {} // utils.c
	wget_vector_set_destructor(NULL, NULL); // vector.c
	wget_free(wget_malloc(1)); // xalloc.c
}

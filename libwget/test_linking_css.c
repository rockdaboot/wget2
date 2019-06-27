// Just a test for static linking.
// We call one function from each object file in libwget.
// Unresolved references should come up on linking.

#include <config.h>
#include <wget.h>

int main(void)
{
	wget_css_parse_buffer((const char *)1, 0, NULL, NULL, NULL); // css.c
}

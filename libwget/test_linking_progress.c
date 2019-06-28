// Just a test for static linking.
// We call one function from each object file in libwget_progress
// Unresolved references should come up on linking.

#include <config.h>
#include <wget.h>

int main(void)
{
	wget_bar *bar = wget_bar_init(NULL, 1);

	if (bar) {
		wget_bar_set_slots(bar, 2);
		wget_bar_free(&bar);
	}
}

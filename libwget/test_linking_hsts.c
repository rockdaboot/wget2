// Just a test for static linking.
// We call one function from each object file in libwget_thread
// Unresolved references should come up on linking.

#include <config.h>
#include <wget.h>

int main(void)
{
	wget_hsts_db_deinit(wget_hsts_db_init(NULL, NULL));
}

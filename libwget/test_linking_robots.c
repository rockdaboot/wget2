// Just a test for static linking.
// We call one function from each object file in libwget_thread
// Unresolved references should come up on linking.

#include <config.h>
#include <wget.h>

int main(void)
{
	wget_robots *robots;

	wget_robots_parse(&robots, "/", NULL);
	wget_robots_free(&robots);
}

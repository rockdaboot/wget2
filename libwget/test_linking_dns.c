// Just a test for static linking.
// We call one function from each object file in libwget_thread
// Unresolved references should come up on linking.

#include <config.h>
#include <wget.h>

int main(void)
{
	wget_dns *dns;

	wget_dns_init(&dns);
	wget_dns_resolve(dns, "localhost", 80, 0, 0);
	wget_dns_free(&dns);
}

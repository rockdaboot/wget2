// Just a test for static linking.
// We call one function from each object file in libwget_thread
// Unresolved references should come up on linking.

#include <config.h>
#include <wget.h>

int main(void)
{
	wget_dns_cache *cache;

	wget_dns_cache_init(&cache);
	wget_dns_cache_add(cache, "localhost", 0, NULL);
	wget_dns_cache_free(&cache);
}

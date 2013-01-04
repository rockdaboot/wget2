#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#include <libmget.h>

#include "../src/stringmap.h"

static int G_GNUC_MGET_NONNULL_ALL _print_word(const char *word)
{
	printf("%s\n", word);
	return 0;
}

int main(int argc, const char *const *argv)
{
	int fd, it, unique = 0, duple = 0;
	char *buf, *word, *end;
	size_t length;
	struct stat st;
	MGET_STRINGMAP *map = stringmap_create(1024);

	for (it = 1; it < argc; it++) {
		if ((fd = open(argv[it], O_RDONLY)) == -1) {
			fprintf(stderr, "Failed to read open %s\n", argv[it]);
			continue;
		}

		if (fstat(fd, &st)) {
			fprintf(stderr, "Failed to stat %s\n", argv[it]);
			close(fd);
			continue;
		}

		length = st.st_size;

		if (!(buf = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0))) {
			fprintf(stderr, "Failed to mmap %s (%d)\n", argv[it], errno);
			close(fd);
			continue;
		}

		buf[length] = 0;

		for (word = buf; *word; word = end) {
			while (*word && !isalnum(*word)) word++;
			for (end = word; *end && isalnum(*end);) end++;
			if (word != end) {
				char c = *end;
				*end = 0;

/*				if (stringmap_get(map, word)) {
					duple++;
				} else {
					stringmap_put_ident_noalloc(map, strndup(word, end - word));
					unique++;
				}
*/
				if (stringmap_put_ident(map, word))
					duple++;
				else
					unique++;

				*end = c;
			}
		}

		munmap(buf, length);
		close(fd);
	}

	printf("read %u words, %u uniques, %u doubles\n", unique + duple, unique, duple);

	// const void *keys = stringmap_get_keys(map);
	stringmap_browse(map, (int(*)(const char *, const void *))_print_word);

	stringmap_free(&map);
	
	return 0;
}

/*
 * Copyright(c) 2012 Tim Ruehsen
 *
 * This file is part of MGet.
 *
 * Mget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Mget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Mget.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * testing performance of hashmap/stringmap routines
 *
 * Changelog
 * 06.07.2012  Tim Ruehsen  created
 *
 */

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
	MGET_STRINGMAP *map = mget_stringmap_create(1024);

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
				if (mget_stringmap_put_ident(map, word))
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
	mget_stringmap_browse(map, (int(*)(const char *, const void *))_print_word);

	mget_stringmap_free(&map);
	
	return 0;
}

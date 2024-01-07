/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * testing performance of buffer printf routines
 *
 * Changelog
 * 06.07.2012  Tim Ruehsen  created
 *
 */

#include <config.h>

#include <stdio.h>

#include <wget.h>

int main(void)
{
	wget_buffer buf;
	char sbuf[128];

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));

	for (unsigned it = 0; it < 10000000; it++) {
		// buffer: 0.239s  libc: 0.018s (gcc replaces sprintf(%s) by strcpy())
//		snprintf(sbuf,sizeof(sbuf),"%s", "teststring sabbeldi heidewitzka\n");
//		buffer_printf(&buf,"%s", "teststring sabbeldi heidewitzka\n");

		// buffer: 0.306s  libc: 1.040s
//		sprintf(sbuf,"%s\n", "teststring sabbeldi heidewitzka\n");
//		buffer_printf(&buf,"%s\n", "teststring sabbeldi heidewitzka\n");

		// function call and loop overhead: buffer: 0.072s libc: 0.390s
//		buffer_printf(&buf, "", "teststring sabbeldi heidewitzka\n");
//		sprintf(sbuf, "", "teststring sabbeldi heidewitzka\n");

		// buffer: 0.392s  libc: 0.838s
//		sprintf(sbuf,"%.*s\n", 17, "teststring sabbeldi heidewitzka\n");
//		buffer_printf(&buf,"%.*s\n", 17, "teststring sabbeldi heidewitzka\n");

		// buffer: 0.407s  libc: 0.960s
//		sprintf(sbuf,"%d\n", it);
//		buffer_printf(&buf,"%d\n", it);

		// buffer: 0.643s  libc/sprintf: 1.251s  libc/snprintf: 1.253s
//		snprintf(sbuf,sizeof(sbuf),"%10.*d\n", 8, it);
//		sprintf(sbuf,"%10.*d\n", 8, it);
//		buffer_printf(&buf,"%10.*d\n", 8, it);

		// buffer: 0.456s  libc: 0.867s
//		sprintf(sbuf,"%X\n", it);
		wget_buffer_printf(&buf, "%X\n", it);

		// buffer: 0.955s  libc: 1.648s
//		sprintf(sbuf,"teststring %s sabbeldi %d\n", "[foobar foobar foobar]", it);
//		buffer_printf(&buf,"teststring %s sabbeldi %d\n", "[foobar foobar foobar]", it);
	}

	wget_buffer_deinit(&buf);

	return 0;
}

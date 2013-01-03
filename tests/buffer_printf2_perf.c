#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>

#include <libmget.h>

#include "../src/buffer.h"

#define buffer_strcat(buf, s) \
 

int main(void)
{
	int it;
	char sbuf[128];
	mget_buffer_t buf;

	buffer_init(&buf,sbuf,sizeof(sbuf));

	for (it = 0; it < 10000000; it++) {
		// buffer: 0.239s  libc: 0.018s (gcc replaces sprintf(%s) by strcpy())
//		snprintf(sbuf,sizeof(sbuf),"%s", "teststring sabbeldi heidewitzka\n");
//		buffer_printf2(&buf,"%s", "teststring sabbeldi heidewitzka\n");

		// buffer: 0.306s  libc: 1.040s
//		sprintf(sbuf,"%s\n", "teststring sabbeldi heidewitzka\n");
//		buffer_printf2(&buf,"%s\n", "teststring sabbeldi heidewitzka\n");

		// function call and loop overhead: buffer: 0.072s libc: 0.390s
//		buffer_printf2(&buf, "", "teststring sabbeldi heidewitzka\n");
//		sprintf(sbuf, "", "teststring sabbeldi heidewitzka\n");

		// buffer: 0.392s  libc: 0.838s
//		sprintf(sbuf,"%.*s\n", 17, "teststring sabbeldi heidewitzka\n");
//		buffer_printf2(&buf,"%.*s\n", 17, "teststring sabbeldi heidewitzka\n");

		// buffer: 0.407s  libc: 0.960s
//		sprintf(sbuf,"%d\n", it);
//		buffer_printf2(&buf,"%d\n", it);

		// buffer: 0.643s  libc/sprintf: 1.251s  libc/snprintf: 1.253s
//		snprintf(sbuf,sizeof(sbuf),"%10.*d\n", 8, it);
//		sprintf(sbuf,"%10.*d\n", 8, it);
//		buffer_printf2(&buf,"%10.*d\n", 8, it);

		// buffer: 0.456s  libc: 0.867s
//		sprintf(sbuf,"%X\n", it);
		buffer_printf2(&buf,"%X\n", it);

		// buffer: 0.955s  libc: 1.648s
//		sprintf(sbuf,"teststring %s sabbeldi %d\n", "[foobar foobar foobar]", it);
//		buffer_printf2(&buf,"teststring %s sabbeldi %d\n", "[foobar foobar foobar]", it);
	}

	buffer_deinit(&buf);

	return 0;
}

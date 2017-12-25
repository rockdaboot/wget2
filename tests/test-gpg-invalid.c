/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Testing an invalid signature.
 */

#include <config.h>
#include <stdlib.h> // exit()
#include "gpg-test-util.h"



int main(void)
{
#ifdef WITH_GPGME
	if (gpg_test(SRCDIR "/gpg/helloworld.txt.invalid.sig", 10)) { // WG_EXIT_STATUS_SIG_CHECK_FAIL
		return 1;
	}
#endif

	exit(0);
}
